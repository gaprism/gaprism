"""The blocklist downloads against the real providers. Needs the network: ``pytest -m live``.

The files go into a temporary directory (nothing of the installation is touched). The test notices
when a provider moves or reshapes its file, when a download is refused (URLhaus asks for an
Auth-Key for its API, not for the host file), and when a list becomes so much smaller than the
minimum sizes of ``app/service/blocklists.py`` that the update would refuse it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome
from app.checks.blocklists import BlocklistsCheck
from app.service import blocklists
from app.service.blocklists import PROVIDERS, BlocklistData

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def installed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """What ``flask datasets update`` makes of the real files (downloaded once for the module)."""
    directory = tmp_path_factory.mktemp("blocklists")
    with httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(30.0, read=120.0),
        headers={"User-Agent": "Gaprism/0.1 (+https://github.com/gaprism/gaprism)"},
        trust_env=False,
    ) as client:
        reports = blocklists.update(directory, client)
    failed = {r.kind: r.detail for r in reports if r.status != "updated"}
    assert not failed, failed
    return directory


def a_listed_name(directory: Path, key: str) -> str:
    connection = sqlite3.connect(directory / PROVIDERS[key].filename)
    try:
        row = connection.execute(
            "SELECT name FROM domains ORDER BY name LIMIT 1 OFFSET 7"
        ).fetchone()
    finally:
        connection.close()
    assert row is not None, f"{key} lists no host name"
    return str(row[0])


def test_the_three_real_lists_download_and_are_built(installed: Path) -> None:
    snapshot = BlocklistData(installed).snapshot()
    feeds = {feed.key: feed for feed in snapshot.feeds}
    assert set(feeds) == set(PROVIDERS) and snapshot.problem is None
    assert all(not feed.stale for feed in feeds.values())
    assert feeds["phishing"].domains > 50_000 and feeds["phishing"].addresses > 100
    assert feeds["urlhaus"].domains > 10 and feeds["urlhaus"].published  # the file dates itself
    assert feeds["feodo"].addresses >= 0 and feeds["feodo"].published


def test_a_listed_name_is_found_again_and_a_big_site_is_not(installed: Path) -> None:
    data = BlocklistData(installed)
    for key in ("urlhaus", "phishing"):
        name = a_listed_name(installed, key)
        assert key in data.lookup([name], []).names[name]
    nobody = data.lookup(["www.google.com", "github.com", "example.com", "www.cisa.gov"], [])
    assert nobody.names == {} and nobody.unreadable == ()


def test_the_check_reads_the_installed_files(installed: Path) -> None:
    name = a_listed_name(installed, "phishing")
    ctx = CheckContext(
        domain=name,
        hostname=name,
        config={"DATASETS_DIR": str(installed)},
        http=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(500))),
        previous={"dns": _resolving(name)},
    )
    outcome = BlocklistsCheck().run(ctx)
    assert outcome.status == "ok" and outcome.data["names"][0]["listed_on"], outcome.data
    assert [f["key"] for f in outcome.data["feeds"]] == list(PROVIDERS)


def _resolving(name: str) -> CheckOutcome:
    return CheckOutcome("ok", data={"addresses": [], "cname": [], "canonical_name": name})
