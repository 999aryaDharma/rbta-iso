"""Leaf TLS yang di-pin harus diterima tanpa rantai penerbit (regresi Python 3.11 vs 3.13)."""
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from src.ingestion.wazuh_client import WazuhIndexerClient

openssl = shutil.which("openssl")
pytestmark = pytest.mark.skipif(openssl is None, reason="openssl CLI tidak tersedia")


def _make_leaf_signed_by_ca(tmp_path: Path):
    def run(*args):
        subprocess.run([openssl, *args], cwd=tmp_path, check=True, capture_output=True)

    (tmp_path / "ext.cnf").write_text("subjectAltName=DNS:localhost\n")
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
        "-subj", "/CN=test-ca", "-days", "1")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "leaf.csr", "-subj", "/CN=localhost")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "leaf.pem", "-days", "1", "-extfile", "ext.cnf")
    return tmp_path / "leaf.pem", tmp_path / "key.pem"


def test_pinned_leaf_without_issuer_is_accepted(tmp_path: Path):
    leaf_pem, key_pem = _make_leaf_signed_by_ca(tmp_path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(leaf_pem, key_pem)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = WazuhIndexerClient(
            base_url=f"https://localhost:{server.server_port}", verify_tls=str(leaf_pem), max_retries=1
        )
        assert client._request("GET", "/").status_code == 200
    finally:
        server.shutdown()
