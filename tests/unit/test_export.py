"""Pruebas de la exportación a HTML y PDF (RF-14).

Incluye una prueba de inyección: una evidencia con HTML/JavaScript procedente
del sitio analizado tiene que salir escapada en el informe.
"""

import pytest
from typer.testing import CliRunner

from escaner.cli import app
from escaner.models import Category, ScanContext, ScanResult
from escaner.reporting import html_report
from escaner.reporting.html_report import render_html, safe_reference, write_pdf
from escaner.rules import finding
from escaner.scoring import score_result
from escaner.storage import Storage

XSS = "<script>alert(1)</script><img src=x onerror=alert(2)>"
runner = CliRunner()

AI = {
    "model": "ollama:qwen2.5:3b",
    "created_at": "2026-11-17T15:00:00+00:00",
    "content": {
        "resumen": "Resumen <b>con etiquetas</b>",
        "nota_explicada": "Nota D (60.0/100).",
        "plan": [
            {
                "prioridad": 1,
                "hallazgos": ["HSTS_MISSING"],
                "accion": "Activar HSTS",
                "por_que": "Evita la degradación a HTTP.",
                "esfuerzo": "bajo",
                "configuracion": 'add_header Strict-Transport-Security "max-age=31536000";',
            }
        ],
        "pendientes": [{"id": "CSP_MISSING", "severidad": "media", "titulo": "Falta CSP"}],
        "servidor_web": "nginx",
    },
}


@pytest.fixture
def stored(tmp_path):
    url = "https://ejemplo.es/"
    ctx = ScanContext(url, final_url=url)
    r = score_result(
        ScanResult(
            ctx,
            [
                finding("HSTS_MISSING", "sin cabecera"),
                finding("CSP_MISSING", XSS),
                finding("SECURITY_TXT_PRESENT", "/.well-known/security.txt"),
            ],
            {Category.HEADERS, Category.PATHS},
        )
    )
    store = Storage(tmp_path / "escaner.db")
    scan_id = store.save(r)
    return store, scan_id


def test_html_contiene_nota_categorias_y_hallazgos(stored):
    store, scan_id = stored
    html = render_html(store.get_scan(scan_id))
    assert "ejemplo.es" in html and "Cabeceras de seguridad" in html
    assert "HSTS_MISSING" in html and "Buenas prácticas detectadas (1)" in html
    assert "no evaluada en este modo" in html  # TLS no se evaluó en este escaneo
    assert "Plan priorizado" not in html


def test_evidencia_maliciosa_sale_escapada(stored):
    store, scan_id = stored
    html = render_html(store.get_scan(scan_id), AI)
    assert "<script>alert(1)" not in html and "onerror=alert(2)>" not in html
    assert "&lt;script&gt;" in html
    assert "<b>con etiquetas</b>" not in html  # el texto de la IA también se escapa


def test_csp_prohibe_scripts_y_recursos_externos(stored):
    store, scan_id = stored
    html = render_html(store.get_scan(scan_id))
    assert "default-src 'none'" in html
    assert "<script" not in html and "http://" not in html.split("<body>")[0]


def test_incluye_informe_de_ia_con_aviso(stored):
    store, scan_id = stored
    html = render_html(store.get_scan(scan_id), AI)
    assert "Plan priorizado" in html and "ollama:qwen2.5:3b" in html
    assert "Strict-Transport-Security" in html and "CSP_MISSING" in html
    assert "no los decide la IA" in html


def test_solo_se_enlazan_referencias_https_del_catalogo():
    assert safe_reference("HSTS_MISSING").startswith("https://")
    assert safe_reference("REGLA_QUE_NO_EXISTE") is None


def test_pdf_con_xhtml2pdf(stored, tmp_path, monkeypatch):
    pytest.importorskip("xhtml2pdf")
    store, scan_id = stored
    import builtins

    real_import = builtins.__import__

    def no_weasy(name, *args, **kwargs):  # fuerza el motor alternativo
        if name == "weasyprint":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_weasy)
    out = tmp_path / "informe.pdf"
    assert write_pdf(render_html(store.get_scan(scan_id), AI), out) == "xhtml2pdf"
    assert out.read_bytes().startswith(b"%PDF")
    assert html_report.PDF_REPLACEMENTS["≥"] == ">="


def test_pdf_sin_motores_da_error_claro(tmp_path, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def none(name, *args, **kwargs):
        if name in {"weasyprint", "xhtml2pdf"}:
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", none)
    with pytest.raises(html_report.ExportError, match="pip install"):
        write_pdf("<html></html>", tmp_path / "x.pdf")


def test_cli_export_html_con_ia(stored, tmp_path, monkeypatch):
    store, scan_id = stored
    store.save_report(scan_id, "divulgativo", AI["model"], AI["content"])
    monkeypatch.setenv("ESCANER_DATA_DIR", str(tmp_path))
    out = tmp_path / "informe.html"
    res = runner.invoke(app, ["export", str(scan_id), "-f", "html", "-o", str(out)])
    assert res.exit_code == 0, res.output
    assert (
        "con informe de IA" in " ".join(res.output.split()) and "Plan priorizado" in out.read_text()
    )


def test_cli_export_no_ai_y_formato_invalido(stored, tmp_path, monkeypatch):
    _, scan_id = stored
    monkeypatch.setenv("ESCANER_DATA_DIR", str(tmp_path))
    out = tmp_path / "i.html"
    res = runner.invoke(app, ["export", str(scan_id), "--no-ai", "-o", str(out)])
    assert res.exit_code == 0 and "sin informe de IA" in " ".join(res.output.split())
    assert runner.invoke(app, ["export", str(scan_id), "-f", "docx"]).exit_code == 2
