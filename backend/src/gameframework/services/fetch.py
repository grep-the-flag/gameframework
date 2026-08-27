"""`fetch_hardened` — the one hardened HTTP fetch every registry/theme/
language/`event.yaml` fetch reuses (api-surface.md §2.6, M2-Task-Plan.md
Task 11). The mechanics are fixed by the document, not left to the
implementer, because each is a distinct way to get this wrong:

- redirects are followed **manually**, with the client's own following
  disabled, so every hop's scheme and host are checked against the origin
  **before** the next request is issued — never after a body has already
  moved;
- the body is read **streamed against a running byte counter**, never
  trusted from `Content-Length`, which a hostile or merely broken server
  can misstate in either direction;
- archives are expanded **entry by entry**, under both a total
  decompressed cap and a compression-ratio cap — per entry for `zip`
  (independently deflate-compressed entries), whole-stream for `tar.gz`
  (one gzip stream, so decompressed-out over compressed-in is the only
  ratio the format has) — and every member's normalized path must stay
  relative and inside the target directory: no `..`, no absolute path, no
  symlink;
- connect and total deadlines are set explicitly, the total tracked across
  every hop rather than reset by each one.

DNS rebinding and private-address SSRF are **out of scope for v1** — a
recorded decision (M2-Task-Plan.md Task 11), not an oversight: the route is
admin-only, the installation commonly runs against an internal registry
mirror that is legitimately a private address, and an admin already holds
capabilities an SSRF would not add to.

A declared `Content-Type` is a hint, not the source of truth (api-surface.md
§2.6): it is checked against an allowlist that must admit `text/plain` and
`application/octet-stream`, because that is what a raw-file host actually
sends for a `.yaml`. What the payload *is* comes from its own bytes — a
`zip`/`gzip` magic number, or (failing both) an attempt to decode it as
text, which is as far as this module goes; a document that decodes but is
not valid YAML, or valid YAML but not a valid `event.yaml`, is a pipeline
failure for the caller to raise, not a fetch refusal — the same split the
upload path already draws (`event_yaml_invalid` there).
"""

import gzip
import posixpath
import stat
import tarfile
import time
import zipfile
from dataclasses import dataclass
from io import BytesIO
from typing import IO, cast
from urllib.parse import urljoin, urlsplit

import httpx

__all__ = ["FetchCaps", "DEFAULT_CAPS", "FetchError", "fetch_hardened"]


class FetchError(Exception):
    """One of api-surface.md §2.6's refusal codes, all `422`."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(detail or code)
        self.code = code


@dataclass(frozen=True)
class FetchCaps:
    """The caps api-surface.md §2.6 fixes, as a parameter rather than a
    module-level read of settings: production always constructs
    `fetch_hardened` with `DEFAULT_CAPS`, but a function handed its limits
    is testable without waiting out real timeouts or building genuinely
    50 MiB payloads (the same reasoning `mint_csrf_token`'s explicit
    `expires_at` parameter used in Task 3).
    """

    max_download_bytes: int = 10 * 1024 * 1024
    max_decompressed_bytes: int = 50 * 1024 * 1024
    max_compression_ratio: int = 100
    max_redirects: int = 2
    connect_timeout: float = 5.0
    total_timeout: float = 30.0


DEFAULT_CAPS = FetchCaps()

# api-surface.md §2.6: "must include text/plain and application/octet-
# stream, because that is what a raw-file host actually sends for a
# .yaml" — the allowlist is deliberately loose; the bytes decide the rest.
_ALLOWED_CONTENT_TYPES = frozenset(
    {
        "application/x-yaml",
        "application/yaml",
        "text/yaml",
        "text/x-yaml",
        "text/plain",
        "application/octet-stream",
        "application/zip",
        "application/x-zip-compressed",
        "application/gzip",
        "application/x-gzip",
        "application/x-tar",
        "application/x-compressed-tar",
    }
)

_ZIP_MAGIC_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06")
_GZIP_MAGIC = b"\x1f\x8b"
_TARGET_NAME = "event.yaml"
_CHUNK_SIZE = 65536
_RATIO_CHECK_FLOOR = 65536


def _origin_host(url: str) -> str:
    # M2 security gate Task 20, finding: Low. `urlsplit` runs an NFKC-
    # normalization validity check on the authority component and raises
    # a bare `ValueError` for some inputs (a fullwidth `@` among them) --
    # reachable purely from the URL string, before any network request.
    # Left unguarded, this propagated past the module's own contract
    # ("raises FetchError naming the api-surface.md §2.6 code on any
    # refusal") as an unhandled exception. `source_unreachable` is the
    # same code used two lines below for a URL with no hostname at all --
    # both are "cannot identify what to connect to."
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise FetchError("source_unreachable") from exc
    if parsed.scheme != "https":
        raise FetchError("source_not_https")
    if not parsed.hostname:
        raise FetchError("source_unreachable")
    return parsed.hostname


def fetch_hardened(
    url: str,
    *,
    caps: FetchCaps = DEFAULT_CAPS,
    transport: httpx.BaseTransport | None = None,
) -> bytes:
    """Fetches `url` — a raw `event.yaml`, or an archive containing one —
    under every cap above, and returns the `event.yaml` bytes. Raises
    `FetchError` naming the api-surface.md §2.6 code on any refusal.
    `transport` lets a test drive this against an in-process transport
    (`httpx.MockTransport`, `httpx.ASGITransport`) instead of the network.
    """
    origin_host = _origin_host(url)
    current_url = url
    redirects = 0
    started_at = time.monotonic()

    client_kwargs: dict[str, object] = {"follow_redirects": False}
    if transport is not None:
        client_kwargs["transport"] = transport

    with httpx.Client(**client_kwargs) as client:  # type: ignore[arg-type]
        while True:
            remaining = caps.total_timeout - (time.monotonic() - started_at)
            if remaining <= 0:
                raise FetchError("source_unreachable")
            timeout = httpx.Timeout(remaining, connect=min(caps.connect_timeout, remaining))

            try:
                with client.stream("GET", current_url, timeout=timeout) as response:
                    if response.is_redirect:
                        redirects += 1
                        if redirects > caps.max_redirects:
                            raise FetchError("redirect_limit_exceeded")
                        location = response.headers.get("location")
                        if not location:
                            raise FetchError("source_unreachable")
                        next_url = urljoin(current_url, location)
                        next_host = _origin_host(next_url)
                        if next_host != origin_host:
                            raise FetchError("redirect_host_changed")
                        current_url = next_url
                        continue

                    if not (200 <= response.status_code < 300):
                        raise FetchError("source_unreachable")

                    declared_type = response.headers.get("content-type", "").split(";")[0].strip()
                    if declared_type.lower() not in _ALLOWED_CONTENT_TYPES:
                        raise FetchError("content_type_unexpected")

                    payload = _read_capped(response, caps.max_download_bytes)
                    break
            except httpx.TimeoutException as exc:
                raise FetchError("source_unreachable") from exc
            except httpx.TransportError as exc:
                raise FetchError("source_unreachable") from exc

    return _extract_event_yaml(payload, caps)


def _read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    """Streamed against a running counter — `Content-Length` is never
    read for this decision, since a server can misstate it either way."""
    total = 0
    chunks: list[bytes] = []
    for chunk in response.iter_bytes(_CHUNK_SIZE):
        total += len(chunk)
        if total > max_bytes:
            raise FetchError("download_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _extract_event_yaml(payload: bytes, caps: FetchCaps) -> bytes:
    if payload.startswith(_GZIP_MAGIC):
        return _extract_from_targz(payload, caps)
    if payload.startswith(_ZIP_MAGIC_PREFIXES):
        return _extract_from_zip(payload, caps)
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FetchError("content_type_unexpected") from exc
    return payload


def _normalized_safe_path(name: str) -> str:
    """api-surface.md §2.6 / Task 11: "every member is rejected unless its
    normalized path stays relative and inside the target directory — no
    `..`, no absolute path". `posixpath.normpath` collapses `a/../../b`
    into `../b` before the check runs, which is what catches a traversal
    hidden behind an internal `..` segment rather than only a leading one.
    """
    if name.startswith(("/", "\\")):
        raise FetchError("archive_entry_unsafe")
    normalized = posixpath.normpath(name)
    if normalized == ".." or normalized.startswith("../") or posixpath.isabs(normalized):
        raise FetchError("archive_entry_unsafe")
    return normalized


def _basename(normalized_path: str) -> str:
    return posixpath.basename(normalized_path)


def _zip_entry_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode) if mode else False


def _extract_from_zip(payload: bytes, caps: FetchCaps) -> bytes:
    try:
        archive = zipfile.ZipFile(BytesIO(payload))
        infos = archive.infolist()
    except zipfile.BadZipFile as exc:
        raise FetchError("content_type_unexpected") from exc

    total_decompressed = 0
    found: bytes | None = None
    # M2 security gate Task 20, finding: Low. Physical/central-directory
    # order, not `sorted()` by filename — `_extract_from_targz` already
    # walks its own archive format in true stream order, and picking the
    # *lexicographically* first `event.yaml` among several same-basename
    # entries silently diverged from what a standard tool's listing shows
    # first. The two archive formats now agree.
    for info in infos:
        if _zip_entry_is_symlink(info):
            raise FetchError("archive_entry_unsafe")
        normalized = _normalized_safe_path(info.filename)
        if info.is_dir():
            continue
        is_target = _basename(normalized) == _TARGET_NAME and found is None

        entry_decompressed = 0
        target_chunks: list[bytes] = []
        # M2 security gate Task 20, finding: Low. A crafted zip whose
        # local file header disagrees with its central directory entry
        # (same name, patched bytes) parses cleanly through `ZipFile()`/
        # `.infolist()` above — `zipfile` only detects the mismatch here,
        # at `.open()` time, which the outer `try/except BadZipFile` does
        # not cover.
        try:
            member_context = archive.open(info)
        except zipfile.BadZipFile as exc:
            raise FetchError("content_type_unexpected") from exc
        with member_context as member:
            while True:
                chunk = member.read(_CHUNK_SIZE)
                if not chunk:
                    break
                entry_decompressed += len(chunk)
                total_decompressed += len(chunk)
                if total_decompressed > caps.max_decompressed_bytes:
                    raise FetchError("archive_too_large")
                if entry_decompressed > max(info.compress_size, 1) * caps.max_compression_ratio:
                    raise FetchError("archive_too_large")
                if is_target:
                    target_chunks.append(chunk)
        if is_target:
            found = b"".join(target_chunks)

    if found is None:
        raise FetchError("event_yaml_not_found")
    return found


class _CountingGzipReader:
    """Wraps a `gzip.GzipFile` so every byte `tarfile` pulls off it — for
    *every* member, not only the one this fetch wants — is counted against
    the total decompressed cap and the whole-stream compression ratio
    (api-surface.md §2.6: "a `tar.gz` is one stream... its ratio is the
    whole stream's"). `tarfile`'s own stream mode (`r|`) reads sequentially
    through every member's data to reach the next header, which is what
    makes this wrapper see the whole archive regardless of which member
    the caller actually extracts.
    """

    def __init__(self, gzip_file: gzip.GzipFile, compressed_size: int, caps: FetchCaps) -> None:
        self._gzip_file = gzip_file
        self._compressed_size = max(compressed_size, 1)
        self._caps = caps
        self.total_decompressed = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._gzip_file.read(size if size and size > 0 else _CHUNK_SIZE)
        self.total_decompressed += len(chunk)
        if self.total_decompressed > self._caps.max_decompressed_bytes:
            raise FetchError("archive_too_large")
        # `tarfile` pads its output to a full RECORDSIZE block (20 * 512 =
        # 10240 bytes) even for a near-empty archive, and that padding is
        # almost pure zero bytes — gzip compresses it to a few dozen bytes,
        # which alone can clear a 100:1 ratio against a symlink-only or
        # single-tiny-file tar.gz with no bomb in it at all. The floor is
        # comfortably above one RECORDSIZE so mandatory padding never trips
        # the check on its own; a real bomb clears it within one chunk.
        if (
            self.total_decompressed > _RATIO_CHECK_FLOOR
            and self.total_decompressed > self._compressed_size * self._caps.max_compression_ratio
        ):
            raise FetchError("archive_too_large")
        return chunk


def _extract_from_targz(payload: bytes, caps: FetchCaps) -> bytes:
    reader = _CountingGzipReader(gzip.GzipFile(fileobj=BytesIO(payload)), len(payload), caps)
    found: bytes | None = None
    try:
        archive: tarfile.TarFile = tarfile.open(
            fileobj=cast(IO[bytes], reader), mode="r|", ignore_zeros=False
        )
        try:
            for member in archive:
                if member.issym() or member.islnk():
                    raise FetchError("archive_entry_unsafe")
                normalized = _normalized_safe_path(member.name)
                if not member.isfile():
                    continue
                if found is None and _basename(normalized) == _TARGET_NAME:
                    extracted = archive.extractfile(member)
                    if extracted is not None:
                        found = extracted.read()
        finally:
            archive.close()
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise FetchError("content_type_unexpected") from exc

    if found is None:
        raise FetchError("event_yaml_not_found")
    return found
