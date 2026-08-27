"""M2-Task-Plan.md Task 11 Step 3: `fetch_hardened` (api-surface.md §2.6).

Every test drives `fetch_hardened` against `httpx.MockTransport` — no real
network, deterministic and offline (Task 11 briefing). `_transport` below
is keyed by exact URL and raises `AssertionError` on any URL it was not
told to expect, which is what makes "the redirect target was never
requested" a property the transport itself enforces rather than something
each test has to instrument by hand.

For every refusal, the ordering claim ("before the expensive thing") is
bound structurally: a redirect-host test's *first* hop carries a body that
raises if iterated at all; the download-size test's body is an unbounded
generator that would hang forever if `fetch_hardened` read it whole before
counting; the compression-ratio tests use a payload whose ratio trips
inside the *first* 64 KiB chunk, so a bomb many times the cap never has to
exist on disk or in memory for the proof to hold.
"""

import gzip
import io
import stat
import tarfile
import time
import zipfile
from collections.abc import Callable, Iterator

import httpx
import pytest

from gameframework.services.fetch import DEFAULT_CAPS, FetchCaps, FetchError, fetch_hardened

_SMALL_CAPS = FetchCaps(
    max_download_bytes=1024,
    max_decompressed_bytes=4096,
    max_compression_ratio=100,
    max_redirects=2,
    connect_timeout=5.0,
    total_timeout=30.0,
)


def _transport(routes: dict[str, Callable[[httpx.Request], httpx.Response]]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url not in routes:
            raise AssertionError(f"unexpected request to {url} — fetch_hardened went too far")
        return routes[url](request)

    return httpx.MockTransport(handler)


def _ok(
    content: bytes, content_type: str = "application/x-yaml"
) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(
        200, headers={"content-type": content_type}, content=content
    )


def _redirect(location: str) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(302, headers={"location": location})


def _boom_body() -> Iterator[bytes]:
    raise AssertionError("fetch_hardened read a response body it should never have touched")
    yield b""  # pragma: no cover — unreachable, only makes this a generator


def _redirect_with_boom_body(location: str) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(302, headers={"location": location}, content=_boom_body())


def _wrong_type_with_boom_body() -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(
        200, headers={"content-type": "text/html"}, content=_boom_body()
    )


def _infinite_body() -> Iterator[bytes]:
    chunk = b"x" * 65536
    while True:
        yield chunk


def _unbounded_ok() -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(
        200, headers={"content-type": "text/plain"}, content=_infinite_body()
    )


# --------------------------------------------------------------------------
# Scheme, redirects, reachability
# --------------------------------------------------------------------------


def test_refuses_a_non_https_source() -> None:
    with pytest.raises(FetchError) as exc:
        fetch_hardened("http://example.com/event.yaml", caps=DEFAULT_CAPS, transport=_transport({}))
    assert exc.value.code == "source_not_https"


def test_refuses_a_source_with_no_hostname() -> None:
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https:///event.yaml", caps=DEFAULT_CAPS, transport=_transport({}))
    assert exc.value.code == "source_unreachable"


def test_refuses_a_host_change_on_the_second_hop() -> None:
    """The single-hop cross-host test below cannot distinguish "checked
    against the origin on every hop" from "only ever checked once,
    coincidentally on the one hop that exists" — with a single hop, the
    origin and the hop being checked are the same thing. Two hops, same
    host then a different one, is the case that actually needs the check
    to still be armed on the *second* request."""
    transport = _transport(
        {
            "https://origin.example/start": _redirect("https://origin.example/middle"),
            "https://origin.example/middle": _redirect_with_boom_body("https://evil.example/end"),
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/start", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "redirect_host_changed"


def test_refuses_a_redirect_to_a_different_host_before_reading_its_body() -> None:
    transport = _transport(
        {
            "https://origin.example/event.yaml": _redirect_with_boom_body(
                "https://evil.example/event.yaml"
            ),
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "redirect_host_changed"


def test_refuses_a_redirect_downgrading_to_http_with_the_more_specific_code() -> None:
    """api-surface.md §2.6: "the scheme is checked on every hop... a
    redirect from https to http on the same host answers source_not_https
    — the more specific of the two codes"."""
    transport = _transport(
        {
            "https://origin.example/event.yaml": _redirect_with_boom_body(
                "http://origin.example/event.yaml"
            ),
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "source_not_https"


def test_allows_a_redirect_to_the_same_host() -> None:
    transport = _transport(
        {
            "https://origin.example/event.yaml": _redirect("https://origin.example/raw/event.yaml"),
            "https://origin.example/raw/event.yaml": _ok(b"id: demo-heist\n"),
        }
    )
    result = fetch_hardened(
        "https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport
    )
    assert result == b"id: demo-heist\n"


def test_allows_exactly_two_redirects() -> None:
    transport = _transport(
        {
            "https://origin.example/a": _redirect("https://origin.example/b"),
            "https://origin.example/b": _redirect("https://origin.example/c"),
            "https://origin.example/c": _ok(b"id: demo-heist\n"),
        }
    )
    result = fetch_hardened("https://origin.example/a", caps=DEFAULT_CAPS, transport=transport)
    assert result == b"id: demo-heist\n"


def test_refuses_a_third_redirect() -> None:
    transport = _transport(
        {
            "https://origin.example/a": _redirect("https://origin.example/b"),
            "https://origin.example/b": _redirect("https://origin.example/c"),
            "https://origin.example/c": _redirect_with_boom_body("https://origin.example/d"),
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/a", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "redirect_limit_exceeded"


def test_refuses_an_unreachable_source() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, headers={"content-type": "text/plain"}, content=b"down")

    transport = httpx.MockTransport(handler)
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "source_unreachable"


def test_refuses_a_transport_level_connect_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    transport = httpx.MockTransport(handler)
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "source_unreachable"


def test_refuses_a_read_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    transport = httpx.MockTransport(handler)
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "source_unreachable"


def test_refuses_a_redirect_with_no_location_header() -> None:
    transport = _transport(
        {"https://origin.example/event.yaml": lambda request: httpx.Response(302)}
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "source_unreachable"


def test_refuses_when_the_total_deadline_is_exceeded_across_hops() -> None:
    """api-surface.md §2.6: "the total tracked across every hop rather
    than reset by each one". `httpx.MockTransport` runs its handler
    in-process and does not go through the I/O code paths `httpx.Timeout`
    actually watches, so a single handler that merely calls `time.sleep`
    is never interrupted by it — proven directly: the same shape with one
    hop and a 0.5 s sleep against a 0.05 s cap does not raise at all. What
    genuinely enforces the total deadline is `fetch_hardened`'s own
    `remaining <= 0` check at the top of its loop, run before every
    request including the first — hence two hops, each sleeping past the
    cap, with the cap a factor of ten below each individual sleep so
    ordinary wall-clock jitter cannot flip the result. The third URL is
    never registered: the deadline must fire before it would ever be
    requested.
    """

    def sleepy_redirect(location: str) -> Callable[[httpx.Request], httpx.Response]:
        def handler(request: httpx.Request) -> httpx.Response:
            time.sleep(0.03)
            return httpx.Response(302, headers={"location": location})

        return handler

    transport = _transport(
        {
            "https://origin.example/a": sleepy_redirect("https://origin.example/b"),
            "https://origin.example/b": sleepy_redirect("https://origin.example/c"),
        }
    )
    tight_caps = FetchCaps(
        max_download_bytes=DEFAULT_CAPS.max_download_bytes,
        max_decompressed_bytes=DEFAULT_CAPS.max_decompressed_bytes,
        max_compression_ratio=DEFAULT_CAPS.max_compression_ratio,
        max_redirects=DEFAULT_CAPS.max_redirects,
        connect_timeout=DEFAULT_CAPS.connect_timeout,
        total_timeout=0.05,
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/a", caps=tight_caps, transport=transport)
    assert exc.value.code == "source_unreachable"


# --------------------------------------------------------------------------
# Content-Type: a hint checked against an allowlist, never the source of truth
# --------------------------------------------------------------------------


def test_refuses_a_declared_type_outside_the_allowlist_before_reading_its_body() -> None:
    transport = _transport({"https://origin.example/event.yaml": _wrong_type_with_boom_body()})
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "content_type_unexpected"


def test_accepts_text_plain_for_a_raw_event_yaml() -> None:
    """api-surface.md §2.6: the allowlist "must include text/plain and
    application/octet-stream" — what a raw-file host actually sends."""
    transport = _transport(
        {"https://origin.example/event.yaml": _ok(b"id: demo-heist\n", content_type="text/plain")}
    )
    result = fetch_hardened(
        "https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport
    )
    assert result == b"id: demo-heist\n"


def test_accepts_octet_stream_for_a_raw_event_yaml() -> None:
    transport = _transport(
        {
            "https://origin.example/event.yaml": _ok(
                b"id: demo-heist\n", content_type="application/octet-stream"
            )
        }
    )
    result = fetch_hardened(
        "https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport
    )
    assert result == b"id: demo-heist\n"


def test_refuses_a_payload_that_is_neither_yaml_nor_a_supported_archive() -> None:
    """The declared type passes the allowlist (`application/octet-stream`
    covers both legitimate and bogus payloads alike), so what decides is
    the bytes: genuinely undecodable binary is neither a text document nor
    a recognized archive magic number."""
    garbage = bytes(range(256)) * 4  # not valid UTF-8, not zip/gzip magic
    transport = _transport(
        {"https://origin.example/event.yaml": _ok(garbage, content_type="application/octet-stream")}
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.yaml", caps=DEFAULT_CAPS, transport=transport)
    assert exc.value.code == "content_type_unexpected"


# --------------------------------------------------------------------------
# Streamed download cap — never trusted from Content-Length
# --------------------------------------------------------------------------


def test_refuses_a_download_exceeding_the_cap_without_reading_it_whole() -> None:
    """The body is an unbounded generator: if `fetch_hardened` ever tried
    to read it to completion (e.g. trusting a `Content-Length` that was
    never sent, or buffering before counting) this test would hang
    forever rather than fail fast."""
    transport = _transport({"https://origin.example/event.yaml": _unbounded_ok()})
    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.yaml", caps=_SMALL_CAPS, transport=transport)
    assert exc.value.code == "download_too_large"


def test_accepts_a_download_at_exactly_the_cap() -> None:
    payload = b"a" * _SMALL_CAPS.max_download_bytes
    transport = _transport(
        {"https://origin.example/event.yaml": _ok(payload, content_type="text/plain")}
    )
    result = fetch_hardened(
        "https://origin.example/event.yaml", caps=_SMALL_CAPS, transport=transport
    )
    assert result == payload


# --------------------------------------------------------------------------
# Archive extraction: traversal safety, symlinks, missing event.yaml
# --------------------------------------------------------------------------


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _zip_with_symlink(link_name: str, target: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo(link_name)
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, target)
    return buf.getvalue()


def _targz_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _targz_with_symlink(link_name: str, target: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name=link_name)
        info.type = tarfile.SYMTYPE
        info.linkname = target
        tf.addfile(info)
    return buf.getvalue()


def _zip_with_directory(name: str) -> bytes:
    # A directory entry's own name carries the trailing "/" zipfile uses
    # to recognize it (`ZipInfo.is_dir()`); no content, no compression.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name if name.endswith("/") else f"{name}/", b"")
    return buf.getvalue()


def _targz_with_directory(name: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name=name)
        info.type = tarfile.DIRTYPE
        tf.addfile(info)
    return buf.getvalue()


@pytest.mark.parametrize(
    "builder",
    [
        lambda: _zip_bytes({"event.yaml": b"id: demo-heist\n"}),
        lambda: _targz_bytes({"event.yaml": b"id: demo-heist\n"}),
    ],
    ids=["zip", "targz"],
)
def test_extracts_event_yaml_from_a_supported_archive(builder: Callable[[], bytes]) -> None:
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                builder(), content_type="application/octet-stream"
            )
        }
    )
    result = fetch_hardened(
        "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
    )
    assert result == b"id: demo-heist\n"


def _targz_with_directory_and_file(dir_name: str, file_name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        dir_info = tarfile.TarInfo(name=dir_name)
        dir_info.type = tarfile.DIRTYPE
        tf.addfile(dir_info)
        file_info = tarfile.TarInfo(name=file_name)
        file_info.size = len(data)
        tf.addfile(file_info, io.BytesIO(data))
    return buf.getvalue()


@pytest.mark.parametrize(
    "builder",
    [
        lambda: _zip_bytes({"docs/": b"", "event.yaml": b"id: demo-heist\n"}),
        lambda: _targz_with_directory_and_file("docs/", "event.yaml", b"id: demo-heist\n"),
    ],
    ids=["zip", "targz"],
)
def test_extracts_event_yaml_past_a_safe_directory_entry(builder: Callable[[], bytes]) -> None:
    """The negative case for the traversal-directory-entry test above: a
    directory entry whose own path is safe must be tolerated (skipped,
    not confused for content and not refused), which is what proves the
    fix reordered the checks rather than simply removing the `is_dir`
    skip altogether."""
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                builder(), content_type="application/octet-stream"
            )
        }
    )
    result = fetch_hardened(
        "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
    )
    assert result == b"id: demo-heist\n"


@pytest.mark.parametrize(
    "builder",
    [
        lambda: _zip_bytes(
            {"repo-name/event.yaml": b"id: demo-heist\n", "repo-name/README.md": b"hi"}
        ),
        lambda: _targz_bytes(
            {"repo-name/event.yaml": b"id: demo-heist\n", "repo-name/README.md": b"hi"}
        ),
    ],
    ids=["zip", "targz"],
)
def test_finds_event_yaml_nested_under_a_wrapping_directory(builder: Callable[[], bytes]) -> None:
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                builder(), content_type="application/octet-stream"
            )
        }
    )
    result = fetch_hardened(
        "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
    )
    assert result == b"id: demo-heist\n"


@pytest.mark.parametrize(
    "builder",
    [
        lambda: _zip_bytes({"README.md": b"no event here"}),
        lambda: _targz_bytes({"README.md": b"no event here"}),
    ],
    ids=["zip", "targz"],
)
def test_refuses_a_supported_archive_holding_no_event_yaml(builder: Callable[[], bytes]) -> None:
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                builder(), content_type="application/octet-stream"
            )
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
        )
    assert exc.value.code == "event_yaml_not_found"


@pytest.mark.parametrize(
    "builder",
    [
        lambda: _zip_bytes({"../../etc/passwd": b"pwned", "event.yaml": b"id: demo-heist\n"}),
        lambda: _targz_bytes({"../../etc/passwd": b"pwned", "event.yaml": b"id: demo-heist\n"}),
    ],
    ids=["zip", "targz"],
)
def test_refuses_an_archive_with_a_traversal_entry(builder: Callable[[], bytes]) -> None:
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                builder(), content_type="application/octet-stream"
            )
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
        )
    assert exc.value.code == "archive_entry_unsafe"


@pytest.mark.parametrize(
    "builder",
    [
        lambda: _zip_bytes({"/etc/passwd": b"pwned", "event.yaml": b"id: demo-heist\n"}),
        lambda: _targz_bytes({"/etc/passwd": b"pwned", "event.yaml": b"id: demo-heist\n"}),
    ],
    ids=["zip", "targz"],
)
def test_refuses_an_archive_with_an_absolute_path_entry(builder: Callable[[], bytes]) -> None:
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                builder(), content_type="application/octet-stream"
            )
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
        )
    assert exc.value.code == "archive_entry_unsafe"


@pytest.mark.parametrize(
    "builder",
    [
        lambda: _zip_with_symlink("link", "/etc/passwd"),
        lambda: _targz_with_symlink("link", "/etc/passwd"),
    ],
    ids=["zip", "targz"],
)
def test_refuses_an_archive_with_a_symlink_member(builder: Callable[[], bytes]) -> None:
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                builder(), content_type="application/octet-stream"
            )
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
        )
    assert exc.value.code == "archive_entry_unsafe"


@pytest.mark.parametrize(
    "builder",
    [
        lambda: _zip_with_directory("../evil/"),
        lambda: _targz_with_directory("../evil/"),
    ],
    ids=["zip", "targz"],
)
def test_refuses_an_archive_with_a_traversal_directory_entry(builder: Callable[[], bytes]) -> None:
    """A directory entry is a traversal vector like any other member — a
    reader that checks path safety only for files and unconditionally
    skips directories lets `../evil/` straight through. (`fetch.py`'s zip
    path validates every entry, symlink or not, file or directory, before
    ever asking `is_dir()`; this is the test that would have caught it
    when it briefly did not.)"""
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                builder(), content_type="application/octet-stream"
            )
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
        )
    assert exc.value.code == "archive_entry_unsafe"


# --------------------------------------------------------------------------
# Compression ratio: per entry for zip, whole-stream for tar.gz — both
# answer archive_too_large, and both abort inside the first chunk rather
# than after fully decompressing the bomb.
# --------------------------------------------------------------------------


def test_refuses_a_zip_bomb_by_per_entry_ratio() -> None:
    """A single entry whose compressed size is tiny and whose decompressed
    size is ~2,000,000 bytes trips the 100:1 ratio cap inside the very
    first 64 KiB chunk read — the bomb is never materialized."""
    bomb = _zip_bytes({"event.yaml": b"0" * 2_000_000})
    assert len(bomb) < 5_000  # the fixture itself proves the ratio shape
    transport = _transport(
        {"https://origin.example/event.tar.gz": _ok(bomb, content_type="application/octet-stream")}
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
        )
    assert exc.value.code == "archive_too_large"


def test_refuses_a_targz_bomb_by_whole_stream_ratio() -> None:
    """tar.gz has no independent per-entry compressed size (one gzip
    stream for the whole archive), so the ratio is decompressed-out over
    compressed-in for the stream as a whole — still trips inside the
    first chunk for a payload this compressible."""
    bomb = _targz_bytes({"event.yaml": b"0" * 2_000_000})
    assert len(bomb) < 5_000
    transport = _transport(
        {"https://origin.example/event.tar.gz": _ok(bomb, content_type="application/octet-stream")}
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
        )
    assert exc.value.code == "archive_too_large"


_ABSOLUTE_CAP_CAPS = FetchCaps(
    max_download_bytes=1024,
    max_decompressed_bytes=100,
    max_compression_ratio=1_000_000,  # high enough that no entry here trips it
    max_redirects=2,
    connect_timeout=5.0,
    total_timeout=30.0,
)


def test_refuses_a_zip_exceeding_the_absolute_decompressed_cap_without_a_high_ratio() -> None:
    """The negative-of-the-negative: many small, barely-compressible
    entries can clear the *absolute* decompressed cap while never
    individually approaching the ratio cap — a distinct bomb shape from
    the highly-compressible single-entry case above, and this is the
    branch that catches it (fetch.py's `total_decompressed >
    caps.max_decompressed_bytes` check, separate from the per-entry
    ratio check just below it)."""
    incompressible = bytes(range(60))
    bomb = _zip_bytes({"a.bin": incompressible, "event.yaml": incompressible})
    transport = _transport(
        {"https://origin.example/event.tar.gz": _ok(bomb, content_type="application/octet-stream")}
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=_ABSOLUTE_CAP_CAPS, transport=transport
        )
    assert exc.value.code == "archive_too_large"


def test_refuses_a_targz_exceeding_the_absolute_decompressed_cap_without_a_high_ratio() -> None:
    incompressible = bytes(range(60))
    bomb = _targz_bytes({"a.bin": incompressible, "event.yaml": incompressible})
    transport = _transport(
        {"https://origin.example/event.tar.gz": _ok(bomb, content_type="application/octet-stream")}
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=_ABSOLUTE_CAP_CAPS, transport=transport
        )
    assert exc.value.code == "archive_too_large"


def test_accepts_a_zip_entry_under_the_ratio_cap() -> None:
    """The negative case for the ratio check (Working-Agreement: "any
    conditional rule needs its negative case"): incompressible-ish content
    whose ratio stays under 100:1 must not be refused."""
    payload = bytes(range(256)) * 4  # 1024 bytes, deflate barely shrinks this
    bomb = _zip_bytes({"event.yaml": payload})
    transport = _transport(
        {"https://origin.example/event.tar.gz": _ok(bomb, content_type="application/octet-stream")}
    )
    result = fetch_hardened(
        "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
    )
    assert result == payload


def test_accepts_a_targz_entry_under_the_ratio_cap() -> None:
    payload = bytes(range(256)) * 4
    bomb = _targz_bytes({"event.yaml": payload})
    transport = _transport(
        {"https://origin.example/event.tar.gz": _ok(bomb, content_type="application/octet-stream")}
    )
    result = fetch_hardened(
        "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
    )
    assert result == payload


def test_a_malformed_zip_is_refused_as_content_type_unexpected() -> None:
    garbage = b"PK\x03\x04" + bytes(range(256))
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                garbage, content_type="application/octet-stream"
            )
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
        )
    assert exc.value.code == "content_type_unexpected"


def test_a_malformed_targz_is_refused_as_content_type_unexpected() -> None:
    garbage = gzip.compress(b"not a tar stream at all") + b"\x00\x00\x00"
    transport = _transport(
        {
            "https://origin.example/event.tar.gz": _ok(
                garbage, content_type="application/octet-stream"
            )
        }
    )
    with pytest.raises(FetchError) as exc:
        fetch_hardened(
            "https://origin.example/event.tar.gz", caps=DEFAULT_CAPS, transport=transport
        )
    assert exc.value.code == "content_type_unexpected"


def test_an_nfkc_invalid_url_authority_is_refused_as_source_unreachable() -> None:
    """M2 security gate Task 20, finding: Low. `_origin_host` calls
    `urlsplit(url).hostname` with no guard around it; `urlsplit` runs an
    NFKC-normalization validity check on the authority component and
    raises a bare `ValueError` for some inputs — a fullwidth `@` (U+FF20)
    among them, exactly the kind of character a copy-pasted or visually
    spoofed URL can carry. That `ValueError` used to propagate unguarded
    out of `fetch_hardened`, past the one `except FetchError` the calling
    route wraps around it, surfacing as an unhandled `500` on an admin's
    own malformed input instead of one of the nine api-surface.md §2.6
    codes the module's own docstring promises. `source_unreachable` is
    the same code `_origin_host` already answers for a URL with no
    hostname at all — this is the same class of "cannot even identify
    what to connect to" failure, not a new one.
    """
    transport = httpx.MockTransport(
        lambda request: (_ for _ in ()).throw(
            AssertionError(f"fetch_hardened should never reach the network for {request.url}")
        )
    )
    bad_url = "https://origin.example＠evil.com/event.yaml"  # fullwidth '@'

    with pytest.raises(FetchError) as exc:
        fetch_hardened(bad_url, caps=DEFAULT_CAPS, transport=transport)

    assert exc.value.code == "source_unreachable"


def _zip_with_local_header_name_mismatch() -> bytes:
    """A well-formed single-entry zip named `event.yaml`, with the LOCAL
    file header's filename bytes patched in place (same length, so no
    offset in the archive shifts) to disagree with the CENTRAL
    DIRECTORY's copy of the same name. `zipfile.ZipFile(...)` and
    `.infolist()` parse this without complaint — the mismatch is only
    detected when something calls `.open()` on that specific entry.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("event.yaml", b"id: demo-heist\n")
    raw = bytearray(buf.getvalue())
    local_header_offset = raw.find(b"event.yaml")
    assert local_header_offset != -1
    raw[local_header_offset : local_header_offset + len(b"event.yaml")] = b"aaaaaaaaaa"
    return bytes(raw)


def test_a_local_central_header_name_mismatch_is_refused_as_content_type_unexpected() -> None:
    """M2 security gate Task 20, finding: Low. `_extract_from_zip`'s
    `try/except zipfile.BadZipFile` covered only `ZipFile(...)` and
    `.infolist()` — the entry loop's `archive.open(info)` call, where a
    local/central header disagreement is actually detected, sat outside
    that block entirely, so this specific corruption raised an unhandled
    `zipfile.BadZipFile` instead of the same `content_type_unexpected`
    `test_a_malformed_zip_is_refused_as_content_type_unexpected` already
    gets for a different kind of malformed zip.
    """
    payload = _zip_with_local_header_name_mismatch()
    transport = _transport(
        {"https://origin.example/event.zip": _ok(payload, content_type="application/octet-stream")}
    )

    with pytest.raises(FetchError) as exc:
        fetch_hardened("https://origin.example/event.zip", caps=DEFAULT_CAPS, transport=transport)

    assert exc.value.code == "content_type_unexpected"


def test_extracts_the_physically_first_event_yaml_when_two_share_a_basename() -> None:
    """M2 security gate Task 20, finding: Low. `_extract_from_zip` used to
    iterate `sorted(infos, key=lambda i: i.filename)` — lexicographic
    full-path order, not the archive's own physical/central-directory
    order, which is what a human listing the archive with a standard
    tool sees. An archive with two `event.yaml`-named entries at
    different paths therefore let the *lexicographically* first one win
    silently, even when it was physically the second entry in the
    archive. `_extract_from_targz` never had this bug — it walks a true
    tar stream in physical order — so this brings the zip path in line
    with it: the archive's own physical order decides, matching what a
    listing shows first.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("z/event.yaml", b"id: physically-first-entry\n")
        zf.writestr("a/event.yaml", b"id: physically-second-entry\n")
    payload = buf.getvalue()

    physical_order = [info.filename for info in zipfile.ZipFile(io.BytesIO(payload)).infolist()]
    assert physical_order == ["z/event.yaml", "a/event.yaml"]

    transport = _transport(
        {"https://origin.example/event.zip": _ok(payload, content_type="application/octet-stream")}
    )
    result = fetch_hardened(
        "https://origin.example/event.zip", caps=DEFAULT_CAPS, transport=transport
    )

    assert result == b"id: physically-first-entry\n"
