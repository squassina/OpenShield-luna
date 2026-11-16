import datetime
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from openshield.core.tls import (
    CABundleError,
    create_ssl_context,
    resolve_ca_bundle_path,
)
from openshield.integrations.models import IntegrationRegistration, IntegrationUpdate


def write_ca(path: Path) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenShield test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate.public_bytes(serialization.Encoding.DER)


def test_resolves_ca_only_inside_configured_root(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "certs"
    root.mkdir()
    ca_file = root / "private-ca.pem"
    write_ca(ca_file)
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(root))

    assert resolve_ca_bundle_path(str(ca_file)) == ca_file.resolve()


@pytest.mark.parametrize("value", ["relative.pem", "/etc/passwd", "/tmp/outside.pem"])
def test_rejects_ca_paths_outside_root(value: str, tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "certs"
    root.mkdir()
    (tmp_path / "outside.pem").write_text("not a certificate")
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(root))

    with pytest.raises(CABundleError):
        resolve_ca_bundle_path(value)


def test_rejects_symlink_escape(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "certs"
    root.mkdir()
    outside = tmp_path / "outside.pem"
    outside.write_text("not a certificate")
    link = root / "escape.pem"
    link.symlink_to(outside)
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(root))

    with pytest.raises(CABundleError):
        resolve_ca_bundle_path(str(link))


def test_rejects_missing_ca_file(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "certs"
    root.mkdir()
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(root))

    with pytest.raises(CABundleError):
        resolve_ca_bundle_path(str(root / "missing.pem"))


def test_builds_verifying_context_with_private_ca(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "certs"
    root.mkdir()
    ca_file = root / "private-ca.pem"
    certificate_der = write_ca(ca_file)
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(root))

    context = create_ssl_context(str(ca_file), "https://router.example")

    assert context is not None
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert certificate_der in context.get_ca_certs(binary_form=True)


def test_rejects_invalid_ca_and_http_custom_ca(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "certs"
    root.mkdir()
    invalid = root / "invalid.pem"
    invalid.write_text("not a PEM certificate")
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(root))

    with pytest.raises(CABundleError, match="could not be loaded"):
        create_ssl_context(str(invalid), "https://router.example")
    with pytest.raises(CABundleError, match="HTTPS"):
        create_ssl_context(str(invalid), "http://router.example")


def test_integration_models_validate_ca_bundle_path(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "certs"
    root.mkdir()
    ca_file = root / "private-ca.pem"
    write_ca(ca_file)
    outside = tmp_path / "outside.pem"
    write_ca(outside)
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(root))

    registration = IntegrationRegistration(
        integration_id="router-lab",
        kind="openwrt",
        display_name="Router",
        config={"ca_bundle_path": str(ca_file)},
    )
    assert registration.config["ca_bundle_path"] == str(ca_file)
    with pytest.raises(ValueError, match="certificate directory"):
        IntegrationRegistration(
            integration_id="router-lab",
            kind="openwrt",
            display_name="Router",
            config={"ca_bundle_path": str(outside)},
        )
    with pytest.raises(ValueError, match="certificate directory"):
        IntegrationUpdate(config={"ca_bundle_path": str(outside)})
