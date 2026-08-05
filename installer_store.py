"""Download and verify installer assets hosted in a GitHub Release."""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path


class InstallerStoreError(RuntimeError):
    pass


def load_catalog(path: str | os.PathLike) -> dict:
    with open(path, encoding="utf-8") as handle:
        catalog = json.load(handle)
    required = {"repository", "release_tag", "installers"}
    missing = required.difference(catalog)
    if missing:
        raise InstallerStoreError(f"Catalog is missing: {', '.join(sorted(missing))}")
    return catalog


def _release_base(catalog: dict) -> str:
    repository = catalog["repository"].strip("/")
    tag = catalog["release_tag"]
    return f"https://github.com/{repository}/releases/download/{tag}"


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "Python-System-Utility-Toolkit"})
    temporary = destination.with_suffix(destination.suffix + ".part")
    try:
        with urllib.request.urlopen(request, timeout=120) as response, open(temporary, "wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        os.replace(temporary, destination)
    except (OSError, urllib.error.URLError) as exc:
        temporary.unlink(missing_ok=True)
        raise InstallerStoreError(f"Download failed: {url} ({exc})") from exc


def _checksums(catalog: dict, cache_dir: Path) -> dict[str, str]:
    checksum_file = cache_dir / "SHA256SUMS"
    _download(f"{_release_base(catalog)}/SHA256SUMS", checksum_file)
    result = {}
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2:
            result[parts[1].lstrip("*")] = parts[0].lower()
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_installers(catalog: dict, cache_dir: str | os.PathLike) -> list[dict]:
    """Return catalog entries with verified local_path values."""
    cache = Path(cache_dir) / catalog["release_tag"]
    cache.mkdir(parents=True, exist_ok=True)
    checksums = _checksums(catalog, cache)
    prepared = []

    for entry in catalog["installers"]:
        filename = entry["asset"]
        expected = checksums.get(filename)
        if not expected:
            raise InstallerStoreError(f"SHA256SUMS has no checksum for {filename}")
        destination = cache / filename
        if not destination.exists() or sha256(destination) != expected:
            _download(f"{_release_base(catalog)}/{filename}", destination)
        if sha256(destination) != expected:
            destination.unlink(missing_ok=True)
            raise InstallerStoreError(f"Checksum verification failed for {filename}")
        prepared.append({**entry, "local_path": str(destination)})
    return prepared
