"""Phase 10: OpenSSL C context exercise with disposable development certs."""
from pathlib import Path
import subprocess
import tempfile

BASE = Path(__file__).resolve().parents[1]
PROGRAM = BASE / "build" / "tls-gateway"
GENERATOR = BASE / "scripts" / "generate_dev_certs.sh"


def invoke(*arguments):
    return subprocess.run([str(PROGRAM), *map(str, arguments)],
                          capture_output=True, text=True, timeout=10)


def run():
    with tempfile.TemporaryDirectory(prefix="tls-gateway-phase10-") as directory:
        cert_dir = Path(directory) / "certs"
        subprocess.run(["bash", str(GENERATOR), str(cert_dir)],
                       check=True, capture_output=True, text=True, timeout=20)
        certificate = cert_dir / "server.crt"
        key = cert_dir / "server.key"

        good = invoke("--tls-check", certificate, key)
        assert good.returncode == 0, (good.stdout, good.stderr)
        assert "TLS context OK (TLS 1.3 only)" in good.stdout
        assert "memory BIOs ready (no handshake performed)" in good.stdout
        print("PASS: TLS 1.3 context, matched certificate/key, SSL and BIO setup")

        mismatch = invoke("--tls-check", certificate, cert_dir / "ca.key")
        assert mismatch.returncode != 0, mismatch
        assert "TLS configuration check failed" in mismatch.stderr
        print("PASS: mismatched private key rejected")

        absent = invoke("--tls-check", cert_dir / "missing.crt", key)
        assert absent.returncode != 0, absent
        print("PASS: missing certificate rejected")

        bad_usage = invoke("--tls-check", certificate)
        assert bad_usage.returncode == 2
        print("PASS: missing CLI argument rejected")


if __name__ == "__main__":
    run()
