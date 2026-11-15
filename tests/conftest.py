import pytest


@pytest.fixture(autouse=True)
def _base_de_cve_aislada(tmp_path, monkeypatch):
    """Las pruebas nunca usan la base de CVE real del usuario."""
    monkeypatch.setenv("ESCANER_DATA_DIR", str(tmp_path / "datos"))
