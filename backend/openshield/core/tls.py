from __future__ import annotations

import os
import ssl
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_CA_BUNDLE_DIR = "/run/openshield/ca"


class CABundleError(ValueError):
    """Invalid or inaccessible custom CA bundle configuration."""


def resolve_ca_bundle_path(value: str | None) -> Path | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise CABundleError("CA bundle path must be an absolute file inside the certificate directory")

    candidate = Path(value)
    if not candidate.is_absolute():
        raise CABundleError("CA bundle path must be an absolute file inside the certificate directory")

    root_value = os.getenv("OPENSHIELD_CA_BUNDLE_DIR", DEFAULT_CA_BUNDLE_DIR)
    try:
        root = Path(root_value).resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        if not root.is_dir() or not resolved.is_file():
            raise CABundleError("CA bundle must reference an existing file")
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, CABundleError):
            raise
        raise CABundleError("CA bundle must be inside the configured certificate directory") from exc
    return resolved


def create_ssl_context(ca_bundle_path: str | None, url: str) -> ssl.SSLContext | None:
    resolved = resolve_ca_bundle_path(ca_bundle_path)
    if resolved is None:
        return None
    if urlsplit(url).scheme.lower() != "https":
        raise CABundleError("Custom CA bundles require an HTTPS integration URL")
    try:
        context = ssl.create_default_context()
        context.load_verify_locations(cafile=str(resolved))
    except (OSError, ssl.SSLError) as exc:
        raise CABundleError("Custom CA bundle could not be loaded") from exc
    return context
