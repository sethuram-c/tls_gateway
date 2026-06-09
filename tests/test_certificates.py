"""Phase 9: test local CA, SAN issuance and verification using the OpenSSL CLI.

The test generates throwaway files in TemporaryDirectory: no certificate or
private key belongs in the Git repository.
"""
from pathlib import Path
import hashlib
import os
import stat
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "generate_dev_certs.sh"


def command(*argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True, check=check)


def run():
    with tempfile.TemporaryDirectory(prefix="tls-gateway-phase9-") as root:
        output = Path(root) / "certs"
        created = command("bash", str(SCRIPT), str(output))
        assert "generated" in created.stdout.lower(), created.stdout
        expected = {"ca.key", "ca.crt", "server.key", "server.crt"}
        assert {p.name for p in output.iterdir()} == expected

        for secret in (output / "ca.key", output / "server.key"):
            # On POSIX, the restrictive umask must keep private keys private.
            assert stat.S_IMODE(secret.stat().st_mode) == 0o600, secret
            command("openssl", "pkey", "-in", str(secret), "-noout")
        print("PASS: certificate files created and private keys protected")

        leaf = output / "server.crt"
        ca = output / "ca.crt"
        ca_text = command("openssl", "x509", "-in", str(ca), "-noout", "-text").stdout
        leaf_text = command("openssl", "x509", "-in", str(leaf), "-noout", "-text").stdout
        assert "CA:TRUE" in ca_text and "CA:FALSE" in leaf_text
        assert "DNS:localhost" in leaf_text
        assert "IP Address:127.0.0.1" in leaf_text
        assert "TLS Web Server Authentication" in leaf_text
        print("PASS: CA constraints, server purpose and DNS/IP SAN fields")

        for flag, name in (("-verify_hostname", "localhost"),
                           ("-verify_ip", "127.0.0.1")):
            result = command("openssl", "verify", "-CAfile", str(ca),
                             "-purpose", "sslserver", flag, name, str(leaf))
            assert ": OK" in result.stdout, result.stdout
        print("PASS: CA chain and hostname/IP verification")

        wrong = command("openssl", "verify", "-CAfile", str(ca),
                        "-verify_hostname", "wrong.local", str(leaf), check=False)
        assert wrong.returncode != 0, "wrong hostname unexpectedly accepted"
        print("PASS: wrong hostname rejected")

        before = hashlib.sha256((output / "server.key").read_bytes()).digest()
        repeated = command("bash", str(SCRIPT), str(output), check=False)
        assert repeated.returncode != 0, "script overwrote the existing certificates"
        after = hashlib.sha256((output / "server.key").read_bytes()).digest()
        assert before == after, "existing server key changed"
        print("PASS: repeated generation safely refuses to overwrite files")


if __name__ == "__main__":
    run()
