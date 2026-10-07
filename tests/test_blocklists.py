"""The blocklists: reading the three providers' files, building the databases, looking up, updating.

The samples are real: the first lines of each file as the providers published them on 2026-10-07
(the host names of the URLhaus sample are replaced by made-up ones, the rest is as it came).
"""

from __future__ import annotations

import datetime
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest

from app.service import blocklists
from app.service.blocklists import (
    NEVER_LISTED,
    PROVIDERS,
    URLS,
    BlocklistData,
    Source,
    build_database,
    normalise_address,
    normalise_name,
    parse_address_list,
    parse_domain_list,
    parse_hostfile,
)
from app.service.geo.datasets import DatasetError, read_manifest

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "blocklists"
NOW = datetime.datetime(2026, 10, 7, 12, 0, tzinfo=datetime.UTC)
TODAY = NOW.date()
URLHAUS = (FIXTURES / "urlhaus_hostfile.txt").read_text(encoding="utf-8")
FEODO = (FIXTURES / "feodo_recommended.txt").read_text(encoding="utf-8")
PHISHING_DOMAINS = (FIXTURES / "phishing_domains.txt").read_text(encoding="utf-8")
PHISHING_ADDRESSES = (FIXTURES / "phishing_ips.txt").read_text(encoding="utf-8")


def served(files: dict[str, str | int]) -> httpx.Client:
    """A client that serves ``files`` by URL (a number is a status code to answer with)."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = files.get(str(request.url), 404)
        if isinstance(body, int):
            return httpx.Response(body)
        return httpx.Response(200, text=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def everything(changes: Mapping[str, str | int] | None = None) -> dict[str, str | int]:
    """What the three providers serve (their sample files), with ``changes`` by URL on top."""
    urls = {p.key: [s.url for s in p.sources] for p in PROVIDERS.values()}
    files: dict[str, str | int] = {
        urls["urlhaus"][0]: URLHAUS,
        urls["phishing"][0]: PHISHING_DOMAINS,
        urls["phishing"][1]: PHISHING_ADDRESSES,
        urls["feodo"][0]: FEODO,
    }
    return {**files, **(changes or {})}


def written(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def install(directory: Path, key: str, **texts: str) -> None:
    """Build the file of provider ``key`` from small texts (``domains=`` and ``addresses=``)."""
    provider = PROVIDERS[key]
    downloads = {
        kind: written(directory, f"{key}-{kind}.txt", text) for kind, text in texts.items()
    }
    build_database(provider, downloads, directory / provider.filename, NOW, relaxed=True)  # afresh


# ------------------------------------------------------------------------------ names and files


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Shop.Example.COM", "shop.example.com"),
        ("example.com.", "example.com"),
        ("  example.com  ", "example.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("localhost", None),  # one label is not a host of the internet
        ("exa mple.com", None),
        ("-bad-.example.com", None),
        ("", None),
        ("a." * 130 + "com", None),  # longer than a name can be
    ],
)
def test_a_host_name_is_normalised_or_refused(raw: str, expected: str | None) -> None:
    assert normalise_name(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.7", "203.0.113.7"),
        ("[2001:DB8::1]", "2001:db8::1"),
        ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
        ("203.0.113.256", None),
        ("example.com", None),
    ],
)
def test_an_address_is_normalised_or_refused(raw: str, expected: str | None) -> None:
    assert normalise_address(raw) == expected


def test_the_urlhaus_host_file_is_read_as_hosts_with_its_comments_left_out() -> None:
    names, addresses = parse_hostfile(URLHAUS)
    assert len(names) == 43 and addresses == set()
    assert "compromised-01.sample.example" in names and "127.0.0.1" not in names
    assert "3.zhzy999.net3.zhzy999.net" in names  # odd entries are kept as they are
    assert not any(name.startswith("#") for name in names)


def test_a_host_file_may_name_an_address_too() -> None:
    names, addresses = parse_hostfile("# x\n127.0.0.1\tbad.example.com\n127.0.0.1\t203.0.113.9\n\n")
    assert names == {"bad.example.com"} and addresses == {"203.0.113.9"}


def test_the_phishing_domains_are_read_one_per_line() -> None:
    names = parse_domain_list(PHISHING_DOMAINS)
    assert len(names) == 50 and "000webhostapp.com" not in names
    assert "00000000920.us-south.cf.appdomain.cloud" in names


def test_lines_that_are_not_hosts_are_dropped_from_a_domain_list() -> None:
    text = (
        "good.example.com\nGOOD2.Example.COM.\n# comment\nnot a host\n\nx.example # note\n"
        + "z" * 5000
    )
    assert parse_domain_list(text) == {"good.example.com", "good2.example.com", "x.example"}


def test_the_phishing_addresses_and_the_feodo_list_are_read_as_addresses() -> None:
    addresses, declared = parse_address_list(PHISHING_ADDRESSES)
    assert len(addresses) == 40 and declared is None and "100.25.1.9" in addresses
    feodo, count = parse_address_list(FEODO)
    assert feodo == {"50.16.16.211"} and count == 1  # the list counts what it holds


# ------------------------------------------------------------------------------ the databases


def test_a_database_is_built_from_a_download_and_says_what_it_holds(tmp_path: Path) -> None:
    source = written(tmp_path, "hostfile.txt", URLHAUS)
    feed = build_database(
        PROVIDERS["urlhaus"], {"domains": source}, tmp_path / "urlhaus.sqlite", NOW, relaxed=True
    )
    assert (feed.key, feed.as_of, feed.published) == ("urlhaus", "2026-10-07", "2026-10-07")
    assert (feed.domains, feed.addresses, feed.stale) == (43, 0, False)
    again = blocklists.installed_feed(PROVIDERS["urlhaus"], tmp_path / "urlhaus.sqlite", TODAY)
    assert again == feed


def test_a_list_that_is_far_smaller_than_the_real_one_is_refused(tmp_path: Path) -> None:
    source = written(tmp_path, "domains.txt", PHISHING_DOMAINS)  # 50 of at least 50,000
    with pytest.raises(DatasetError) as refused:
        build_database(
            PROVIDERS["phishing"],
            {"domains": source, "addresses": written(tmp_path, "a.txt", PHISHING_ADDRESSES)},
            tmp_path / "phishing.sqlite",
            NOW,
        )
    assert refused.value.reason == "too_few_entries"


def test_a_provider_with_two_files_holds_both(tmp_path: Path) -> None:
    install(tmp_path, "phishing", domains=PHISHING_DOMAINS, addresses=PHISHING_ADDRESSES)
    feed = blocklists.installed_feed(PROVIDERS["phishing"], tmp_path / "phishing.sqlite", TODAY)
    assert feed is not None and (feed.domains, feed.addresses, feed.published) == (50, 40, None)


def test_the_feodo_list_must_count_what_it_holds(tmp_path: Path) -> None:
    install(tmp_path, "feodo", addresses=FEODO)  # fine: a trailer that agrees
    quiet = "# DstIP\n# END 0 entries\n"
    install(tmp_path, "feodo", addresses=quiet)  # an empty list is a real list
    feed = blocklists.installed_feed(PROVIDERS["feodo"], tmp_path / "feodo.sqlite", TODAY)
    assert feed is not None and feed.addresses == 0

    for text, reason in (
        ("# DstIP\n50.16.16.211\n", "no_trailer"),  # cut short before its own end
        ("# DstIP\n50.16.16.211\n# END 2 entries\n", "count_mismatch"),
        ("", "no_trailer"),
    ):
        path = written(tmp_path, "cut.txt", text)
        with pytest.raises(DatasetError) as refused:
            build_database(
                PROVIDERS["feodo"], {"addresses": path}, tmp_path / "x.sqlite", NOW, relaxed=True
            )
        assert refused.value.reason == reason


def test_big_sites_are_never_kept_and_a_feed_full_of_them_is_refused(tmp_path: Path) -> None:
    some = "www.google.com\ngithub.com\nbad.example.com\n"
    install(tmp_path, "urlhaus", domains=some)
    data = BlocklistData(tmp_path)
    assert data.lookup(["www.google.com", "github.com", "bad.example.com"], []).names == {
        "bad.example.com": ("urlhaus",)
    }
    many = "\n".join(sorted(NEVER_LISTED)[:6]) + "\nbad.example.com\n"
    with pytest.raises(DatasetError) as refused:
        build_database(
            PROVIDERS["urlhaus"],
            {"domains": written(tmp_path, "m.txt", many)},
            tmp_path / "y.sqlite",
            NOW,
            relaxed=True,
        )
    assert refused.value.reason == "implausible"
    assert {"google.com", "www.google.com", "github.com", "www.github.com"} <= NEVER_LISTED


def test_what_is_not_text_or_too_big_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "b.bin"
    binary.write_bytes(b"\x00\x01\x02" * 100)
    with pytest.raises(DatasetError) as not_text:
        build_database(
            PROVIDERS["urlhaus"], {"domains": binary}, tmp_path / "z.sqlite", NOW, relaxed=True
        )
    assert not_text.value.reason == "not_text"
    monkeypatch.setattr(blocklists, "MAX_ROWS", 5)
    with pytest.raises(DatasetError) as too_many:
        build_database(
            PROVIDERS["urlhaus"],
            {"domains": written(tmp_path, "h.txt", URLHAUS)},
            tmp_path / "w.sqlite",
            NOW,
            relaxed=True,
        )
    assert too_many.value.reason == "too_many_rows"


def test_an_installed_file_that_is_garbage_is_unreadable_not_a_crash(tmp_path: Path) -> None:
    path = tmp_path / "urlhaus.sqlite"
    path.write_bytes(b"this is not a database" * 100)
    assert blocklists.installed_feed(PROVIDERS["urlhaus"], path, TODAY) is None
    assert (
        blocklists.installed_feed(PROVIDERS["urlhaus"], tmp_path / "missing.sqlite", TODAY) is None
    )


# ------------------------------------------------------------------------------ looking up


def test_a_name_and_an_address_are_found_with_the_providers_that_list_them(tmp_path: Path) -> None:
    install(tmp_path, "urlhaus", domains="bad.example.com\nboth.example.com\n")
    install(
        tmp_path,
        "phishing",
        domains="both.example.com\nphish.example.net\n",
        addresses="203.0.113.7\n",
    )
    install(tmp_path, "feodo", addresses="203.0.113.7\n2001:db8::1\n# END 2 entries\n")
    data = BlocklistData(tmp_path)
    found = data.lookup(
        ["Bad.Example.COM.", "both.example.com", "clean.example.com"],
        ["203.0.113.7", "2001:0DB8::1", "198.51.100.1"],
    )
    assert found.names == {
        "bad.example.com": ("urlhaus",),
        "both.example.com": ("urlhaus", "phishing"),
    }
    assert found.addresses == {"203.0.113.7": ("phishing", "feodo"), "2001:db8::1": ("feodo",)}


def test_a_lookup_of_nothing_or_of_rubbish_finds_nothing(tmp_path: Path) -> None:
    install(tmp_path, "urlhaus", domains="bad.example.com\n")
    data = BlocklistData(tmp_path)
    assert data.lookup([], []).names == {} and data.lookup(["not a host", ""], ["nope"]).names == {}


def test_a_long_list_of_names_is_looked_up_in_batches(tmp_path: Path) -> None:
    listed = [f"h{n}.example.com" for n in range(0, 1000, 7)]
    install(tmp_path, "urlhaus", domains="\n".join(listed) + "\n")
    asked = [f"h{n}.example.com" for n in range(1000)]
    found = BlocklistData(tmp_path).lookup(asked, [])
    assert sorted(found.names) == sorted(listed) and len(asked) > blocklists.LOOKUP_BATCH


def test_the_snapshot_says_what_is_installed_and_whether_it_is_old(tmp_path: Path) -> None:
    install(tmp_path, "urlhaus", domains="bad.example.com\n")
    install(tmp_path, "feodo", addresses="# END 0 entries\n")
    data = BlocklistData(tmp_path, clock=lambda: TODAY)
    snapshot = data.snapshot()
    assert [f.key for f in snapshot.feeds] == ["urlhaus", "feodo"] and snapshot.problem is None
    assert [f.stale for f in snapshot.feeds] == [False, False]
    later = TODAY + datetime.timedelta(days=blocklists.STALE_AFTER_DAYS + 1)
    assert [f.stale for f in data.snapshot(later).feeds] == [True, True]
    assert (
        data.snapshot(TODAY + datetime.timedelta(days=blocklists.STALE_AFTER_DAYS)).feeds[0].stale
        is False
    )


def test_one_unreadable_file_leaves_the_others_working_and_is_reported(tmp_path: Path) -> None:
    install(tmp_path, "urlhaus", domains="bad.example.com\n")
    (tmp_path / "feodo.sqlite").write_bytes(b"garbage" * 50)
    data = BlocklistData(tmp_path)
    assert [f.key for f in data.snapshot().feeds] == ["urlhaus"]
    assert data.snapshot().problem == "unreadable"
    assert data.lookup(["bad.example.com"], []).names == {"bad.example.com": ("urlhaus",)}


def test_a_file_that_goes_bad_after_it_was_loaded_is_reported_by_the_lookup(tmp_path: Path) -> None:
    install(tmp_path, "urlhaus", domains="bad.example.com\n")
    install(tmp_path, "feodo", addresses="203.0.113.7\n# END 1 entries\n")
    data = BlocklistData(tmp_path)
    assert data.lookup(["bad.example.com"], ["203.0.113.7"]).addresses  # both are loaded
    (tmp_path / "feodo.sqlite").write_bytes(
        b"garbage" * 50
    )  # (the reader has not looked again yet)
    found = data.lookup(["bad.example.com"], ["203.0.113.7"])
    assert found == blocklists.Listings({"bad.example.com": ("urlhaus",)}, {}, ("feodo",))
    assert [f.key for f in data.snapshot().feeds] == ["urlhaus"]  # it looks again, and says so
    assert data.snapshot().problem == "unreadable"


def test_only_the_providers_asked_for_are_consulted(tmp_path: Path) -> None:
    install(tmp_path, "urlhaus", domains="both.example.com\n")
    install(tmp_path, "phishing", domains="both.example.com\n", addresses="203.0.113.7\n")
    (tmp_path / "feodo.sqlite").write_bytes(b"garbage" * 50)
    data = BlocklistData(tmp_path)
    assert data.lookup(["both.example.com"], ["203.0.113.7"], only=["phishing"]) == (
        blocklists.Listings({"both.example.com": ("phishing",)}, {"203.0.113.7": ("phishing",)})
    )
    assert [f.key for f in data.snapshot(only=["phishing"]).feeds] == ["phishing"]
    assert data.snapshot(only=["urlhaus", "phishing"]).problem is None  # feodo is not used
    assert data.snapshot(only=["feodo"]).problem == "unreadable"
    assert data.snapshot(only=[]).feeds == ()


def test_a_file_that_is_replaced_is_read_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(blocklists, "RELOAD_CHECK_SECONDS", 0.0)
    install(tmp_path, "urlhaus", domains="old.example.com\n")
    data = BlocklistData(tmp_path)
    assert data.lookup(["old.example.com"], []).names
    time.sleep(0.02)
    install(tmp_path, "urlhaus", domains="new.example.com\nnewer.example.com\n")
    assert data.lookup(["old.example.com"], []).names == {}
    assert data.snapshot().feeds[0].domains == 2


def test_nothing_installed_knows_nothing(tmp_path: Path) -> None:
    for data in (BlocklistData(tmp_path), blocklists.NOTHING):
        assert data.snapshot().feeds == () and data.lookup(["a.example.com"], ["203.0.113.7"]) == (
            blocklists.Listings({}, {})
        )


def test_one_reader_serves_a_directory_for_the_whole_process(tmp_path: Path) -> None:
    assert blocklists.shared(tmp_path) is blocklists.shared(tmp_path)


# ------------------------------------------------------------------------------ updating


def test_an_update_installs_the_three_providers_and_records_where_they_came_from(
    tmp_path: Path,
) -> None:
    reports = blocklists.update(tmp_path, served(everything()), now=NOW, relaxed=True)
    assert [(r.kind, r.status) for r in reports] == [
        ("urlhaus", "updated"),
        ("phishing", "updated"),
        ("feodo", "updated"),
    ]
    assert "as of 2026-10-07, 43 hosts and 0 addresses" in reports[0].detail
    assert all((tmp_path / p.filename).is_file() for p in PROVIDERS.values())
    manifest = read_manifest(tmp_path)
    assert manifest["urlhaus"]["source"] == "https://urlhaus.abuse.ch/downloads/hostfile/"
    assert manifest["phishing"]["source"].count("https://") == 2
    assert manifest["feodo"]["sha256"] and manifest["feodo"]["build"] == "2026-10-07"
    assert BlocklistData(tmp_path).lookup(["compromised-01.sample.example"], ["50.16.16.211"]) == (
        blocklists.Listings(
            {"compromised-01.sample.example": ("urlhaus",)}, {"50.16.16.211": ("feodo",)}
        )
    )


def test_an_update_can_be_limited_to_the_providers_in_use(tmp_path: Path) -> None:
    reports = blocklists.update(
        tmp_path, served(everything()), now=NOW, relaxed=True, only=["feodo", "urlhaus"]
    )
    assert [(r.kind, r.status) for r in reports] == [("urlhaus", "updated"), ("feodo", "updated")]
    assert not (tmp_path / "phishing.sqlite").exists()
    assert set(read_manifest(tmp_path)) == {"urlhaus", "feodo"}
    assert [s.kind for s in blocklists.status(tmp_path, today=TODAY, only=["feodo"])] == ["feodo"]
    assert blocklists.update(tmp_path, served(everything()), now=NOW, only=[]) == []


def test_a_download_that_is_recent_is_left_alone_unless_forced(tmp_path: Path) -> None:
    blocklists.update(tmp_path, served(everything()), now=NOW, relaxed=True)
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(str(request.url))
        return httpx.Response(500)

    quiet = httpx.Client(transport=httpx.MockTransport(handler))
    soon = NOW + datetime.timedelta(hours=3)
    assert {r.status for r in blocklists.update(tmp_path, quiet, now=soon, relaxed=True)} == {
        "current"
    }
    assert asked == []
    late = NOW + blocklists.REFRESH_AFTER + datetime.timedelta(minutes=1)
    assert {r.status for r in blocklists.update(tmp_path, quiet, now=late, relaxed=True)} == {
        "failed"
    }
    forced = blocklists.update(tmp_path, served(everything()), now=soon, force=True, relaxed=True)
    assert {r.status for r in forced} == {"updated"}


def test_a_provider_that_fails_leaves_the_others_and_its_own_old_file_alone(tmp_path: Path) -> None:
    blocklists.update(tmp_path, served(everything()), now=NOW, relaxed=True)
    later = NOW + datetime.timedelta(days=1)
    broken = everything(
        {PROVIDERS["phishing"].sources[0].url: 503, PROVIDERS["feodo"].sources[0].url: "<html>"}
    )
    reports = blocklists.update(tmp_path, served(broken), now=later, relaxed=True)
    assert [(r.kind, r.status) for r in reports] == [
        ("urlhaus", "updated"),
        ("phishing", "failed"),
        ("feodo", "failed"),
    ]
    assert "http_503" in reports[1].detail and "no_trailer" in reports[2].detail
    data = BlocklistData(tmp_path)
    assert {f.key: f.as_of for f in data.snapshot().feeds} == {
        "urlhaus": "2026-10-08",
        "phishing": "2026-10-07",  # still the old one
        "feodo": "2026-10-07",
    }
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")]  # no temporary files


@pytest.mark.parametrize(
    ("make", "reason"),
    [
        (lambda: httpx.Response(404), "http_404"),
        (lambda: httpx.Response(200, content=b""), "incomplete_download"),
        (
            lambda: httpx.Response(200, headers={"content-length": str(10**9)}, content=b"x"),
            "download_too_large",
        ),
        (lambda: httpx.Response(200, content=b"\x00\x01" * 500), "not_text"),
    ],
)
def test_a_bad_download_is_refused_with_a_stable_reason(
    tmp_path: Path, make: Callable[[], httpx.Response], reason: str
) -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda request: make()))
    (report,) = [
        r for r in blocklists.update(tmp_path, client, now=NOW, relaxed=True) if r.kind == "urlhaus"
    ]
    assert report.status == "failed" and report.detail.endswith(reason)
    assert not (tmp_path / "urlhaus.sqlite").exists()


def test_network_failures_are_typed(tmp_path: Path) -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("secret url inside", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret url inside", request=request)

    for handler, reason in ((slow, "timeout"), (refused, "connection_failed")):
        client = httpx.Client(transport=httpx.MockTransport(handler))
        report = blocklists.update(tmp_path, client, now=NOW, relaxed=True)[0]
        assert report.detail.endswith(reason) and "secret" not in report.detail


def test_the_downloads_are_asked_for_uncompressed(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("accept-encoding", ""))
        return httpx.Response(404)

    blocklists.update(tmp_path, httpx.Client(transport=httpx.MockTransport(handler)), now=NOW)
    # a provider whose first file cannot be had does not ask for its second
    assert set(seen) == {"identity"} and len(seen) == len(PROVIDERS)


def test_the_status_tells_what_is_installed_how_old_it_is_and_where_from(tmp_path: Path) -> None:
    before = {s.kind: s for s in blocklists.status(tmp_path, today=TODAY)}
    assert {k: s.problem for k, s in before.items()} == {
        "urlhaus": "not installed",
        "phishing": "not installed",
        "feodo": "not installed",
    }
    blocklists.update(tmp_path, served(everything()), now=NOW, relaxed=True)
    after = {
        s.kind: s for s in blocklists.status(tmp_path, today=TODAY + datetime.timedelta(days=5))
    }
    assert all(s.present and s.stale and s.age_days == 5 for s in after.values())
    assert after["urlhaus"].source == "https://urlhaus.abuse.ch/downloads/hostfile/"
    assert after["feodo"].sha256 and after["feodo"].build == "2026-10-07"
    (tmp_path / "feodo.sqlite").write_bytes(b"garbage" * 40)
    assert {s.kind: s.problem for s in blocklists.status(tmp_path, today=TODAY)}[
        "feodo"
    ] == "unreadable"


# ------------------------------------------------------------------------------ the sources


def test_the_hosts_the_downloads_come_from_are_the_ones_the_documentation_names() -> None:
    assert {urlsplit(url).hostname for url in URLS} == {
        "urlhaus.abuse.ch",
        "raw.githubusercontent.com",
        "feodotracker.abuse.ch",
    }
    assert all(url.startswith("https://") for url in URLS)


def test_every_provider_names_where_its_terms_are_and_every_file_is_a_known_kind() -> None:
    for provider in PROVIDERS.values():
        assert provider.page.startswith("https://") and provider.licence and provider.filename
        for source in provider.sources:
            assert source.key in ("domains", "addresses")
            assert source.parser in ("hostfile", "domain_list", "address_list")
    assert Source("domains", "https://x.example/", "hostfile", 1).trailer is False
