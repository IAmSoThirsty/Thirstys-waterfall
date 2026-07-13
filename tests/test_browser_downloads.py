"""Tests for encrypted browser download backend."""

from cryptography.fernet import Fernet

from thirstys_waterfall.browser import EncryptedDownloadBackend, IncognitoBrowser


def _browser_config(tmp_path):
    return {
        "incognito_mode": True,
        "no_history": True,
        "no_cache": True,
        "no_cookies": True,
        "tab_isolation": True,
        "sandbox_enabled": False,
        "download_storage_path": str(tmp_path),
        "download_max_bytes": 1024,
    }


def test_encrypted_download_backend_stores_ciphertext_only(tmp_path):
    cipher = Fernet(Fernet.generate_key())
    backend = EncryptedDownloadBackend(tmp_path, cipher)
    url = "data:text/plain,private-download-content"

    result = backend.download_file(
        url=url,
        tab_id="tab-1",
        download_isolated=True,
    )
    artifact = tmp_path / f"{result['download_id']}.twdownload"
    artifact_bytes = artifact.read_bytes()

    assert result["status"] == "completed"
    assert result["content_encrypted"] is True
    assert result["url_encrypted"] is True
    assert result["plaintext_bytes"] == len(b"private-download-content")
    assert b"private-download-content" not in artifact_bytes
    assert b"data:text/plain" not in repr(result).encode()
    assert backend.read_encrypted_artifact(result["download_id"]) == b"private-download-content"


def test_encrypted_download_backend_blocks_network_by_default(tmp_path):
    cipher = Fernet(Fernet.generate_key())
    backend = EncryptedDownloadBackend(tmp_path, cipher)
    url = "https://example.invalid/file.bin"

    result = backend.download_file(
        url=url,
        tab_id="tab-1",
        download_isolated=True,
    )

    assert result["status"] == "unavailable"
    assert result["error"] == "network downloads are disabled by policy"
    assert result["url_encrypted"] is True
    assert b"https://example.invalid" not in repr(result).encode()


def test_incognito_browser_configures_encrypted_download_backend(tmp_path):
    browser = IncognitoBrowser(_browser_config(tmp_path))
    try:
        browser.start()
        tab_id = browser.create_tab()
        result = browser.download_file("data:text/plain,stored-by-browser", tab_id)
        status = browser.get_status()

        assert result["status"] == "completed"
        assert result["backend"] == "EncryptedDownloadBackend"
        assert result["content_encrypted"] is True
        assert status["download_backend_configured"] is True
        assert status["download_backend"] == "EncryptedDownloadBackend"
        assert b"stored-by-browser" not in (tmp_path / f"{result['download_id']}.twdownload").read_bytes()
    finally:
        if browser._active:
            browser.stop()
