"""Address-level rules (ports and CVEs), over what the ports check really produces."""

from __future__ import annotations

from typing import Any

import pytest

from app.checks.base import CheckOutcome
from app.rules import ip_facts
from app.service import exploits as exploit_data
from app.service.ports import PortFacts, PortService, PortsLookup, Vulnerability
from tests.checks.test_ports_check import CLOUDFLARE, FakeProvider, located
from tests.checks.test_ports_check import dns as ports_dns
from tests.checks.test_ports_check import ip_outcome as ports_ip_outcome
from tests.checks.test_ports_check import run as run_ports
from tests.exploit_helpers import FakeExploits, listed, scored
from tests.rules.helpers import fire, host, one

IP = "93.184.216.34"
OTHER = "93.184.216.35"


def services(*ports: tuple[int, str | None, str | None, str | None]) -> tuple[PortService, ...]:
    return tuple(
        PortService(port, transport, product, version)
        for port, transport, product, version in ports
    )


def ports_result(
    hostname: str,
    *,
    address: str = IP,
    ports: tuple[tuple[int, str | None, str | None, str | None], ...] = (),
    vulns: tuple[Vulnerability, ...] = (),
    hostnames: tuple[str, ...] = (),
    shared: bool = False,
    exploits: Any = None,
) -> CheckOutcome:
    facts = PortFacts(
        ip=address,
        provider="shodan",
        services=services(*ports),
        vulnerabilities=vulns,
        hostnames=hostnames,
    )
    previous: dict[str, CheckOutcome] = {"dns": ports_dns(address)}
    if shared:
        previous["ip"] = ports_ip_outcome(located(address, CLOUDFLARE, 13335))
    return run_ports(
        FakeProvider({address: PortsLookup("ok", facts=facts)}),
        previous,
        hostname=hostname,
        exploits=exploits,
    )


def addresses(*hosts: Any) -> Any:
    return ip_facts(list(hosts))


def only_address(*hosts: Any) -> Any:
    found = addresses(*hosts)
    assert len(found) == 1
    return found[0]


# ------------------------------------------------------------------------------ risky ports


@pytest.mark.parametrize(
    ("port", "severity", "service"),
    [
        (21, "medium", "FTP"),
        (22, "medium", "SSH"),
        (23, "high", "Telnet"),
        (445, "high", "SMB"),
        (3306, "high", "MySQL"),
        (3389, "high", "RDP"),
        (5432, "high", "PostgreSQL"),
        (6379, "high", "Redis"),
        (9200, "high", "Elasticsearch"),
        (11211, "high", "Memcached"),
        (27017, "high", "MongoDB"),
    ],
)
def test_each_risky_port_has_its_severity(port: int, severity: str, service: str) -> None:
    facts = only_address(
        host(
            "a.example.com", ports=ports_result("a.example.com", ports=((port, "tcp", None, None),))
        )
    )
    draft = one("RISKY_PORT_EXPOSED", facts)
    assert (draft.severity, draft.confidence) == (severity, "medium")
    assert draft.subject == f"ip:{IP}:{port}"
    assert (draft.params["service"], draft.params["port"], draft.host_id) == (service, port, None)


def test_ordinary_web_ports_are_not_risky() -> None:
    web = ((80, "tcp", "nginx", "1.24"), (443, "tcp", "nginx", "1.24"), (8080, "tcp", None, None))
    assert (
        fire(
            "RISKY_PORT_EXPOSED",
            only_address(host("a.example.com", ports=ports_result("a.example.com", ports=web))),
        )
        == []
    )


def test_every_risky_port_of_an_address_is_its_own_finding_with_its_product() -> None:
    ports = ((22, "tcp", "OpenSSH", "7.4"), (3306, "tcp", "MySQL", "5.7"), (80, "tcp", None, None))
    facts = only_address(host("a.example.com", ports=ports_result("a.example.com", ports=ports)))
    drafts = fire("RISKY_PORT_EXPOSED", facts)
    assert sorted(d.subject for d in drafts) == [f"ip:{IP}:22", f"ip:{IP}:3306"]
    ssh = next(d for d in drafts if d.params["port"] == 22)
    assert (ssh.params["product"], ssh.params["version"]) == ("OpenSSH", "7.4")


def test_a_port_seen_over_tcp_and_udp_is_one_finding() -> None:
    ports = ((11211, "tcp", None, None), (11211, "udp", None, None))
    facts = only_address(host("a.example.com", ports=ports_result("a.example.com", ports=ports)))
    assert len(fire("RISKY_PORT_EXPOSED", facts)) == 1


def test_one_finding_per_address_however_many_hosts_share_it() -> None:
    names = [f"h{n}.example.com" for n in range(8)]
    hosts = [host(n, ports=ports_result(n, ports=((22, "tcp", None, None),))) for n in names]
    drafts = fire("RISKY_PORT_EXPOSED", only_address(*hosts))
    assert len(drafts) == 1
    params = drafts[0].params
    assert params["host_count"] == 8 and params["hosts"] == names[:5]  # listed, bounded
    assert len(params["host_ids"]) == 5


def test_the_attribution_follows_what_the_provider_says() -> None:
    plain = host(
        "a.example.com", ports=ports_result("a.example.com", ports=((22, "tcp", None, None),))
    )
    named = host(
        "b.example.com",
        ports=ports_result(
            "b.example.com", ports=((22, "tcp", None, None),), hostnames=("b.example.com",)
        ),
    )
    assert one("RISKY_PORT_EXPOSED", only_address(plain)).attribution == "ip_only"
    assert one("RISKY_PORT_EXPOSED", only_address(named)).attribution == "hostname_supported"


def test_shared_infrastructure_is_not_the_vendors_server() -> None:
    risky = ((22, "tcp", None, None), (3306, "tcp", None, None))
    cdn = host("a.example.com", ports=ports_result("a.example.com", ports=risky, shared=True))
    facts = only_address(cdn)
    assert facts.attribution == "shared_infrastructure"
    assert fire("RISKY_PORT_EXPOSED", facts) == []
    assert fire("CVE_OBSERVED", facts) == []


def test_an_address_where_any_host_sees_a_cdn_is_shared_for_all_of_them() -> None:
    behind = host(
        "cdn.example.com",
        ports=ports_result("cdn.example.com", ports=((22, "tcp", None, None),), shared=True),
    )
    bare = host(
        "raw.example.com", ports=ports_result("raw.example.com", ports=((22, "tcp", None, None),))
    )
    assert fire("RISKY_PORT_EXPOSED", only_address(behind, bare)) == []


# ------------------------------------------------------------------------------ CVEs


def vulns(*pairs: tuple[str, float | None, bool | None]) -> tuple[Vulnerability, ...]:
    return tuple(Vulnerability(cve, score, None, verified) for cve, score, verified in pairs)


def test_cves_are_one_informational_finding_per_address_with_the_worst_first() -> None:
    reported = vulns(
        ("CVE-2020-0001", 4.3, None),
        ("CVE-2021-0002", 9.8, None),
        ("CVE-2019-0003", None, None),
        ("CVE-2018-0004", 7.5, None),
        ("CVE-2017-0005", 5.0, None),
        ("CVE-2016-0006", 2.1, None),
        ("CVE-2015-0007", 6.1, None),
    )
    facts = only_address(host("a.example.com", ports=ports_result("a.example.com", vulns=reported)))
    draft = one("CVE_OBSERVED", facts)
    assert (draft.severity, draft.confidence, draft.subject) == ("informational", "low", f"ip:{IP}")
    assert draft.params["count"] == 7 and draft.params["max_cvss"] == 9.8
    assert draft.params["top"] == [
        "CVE-2021-0002",
        "CVE-2018-0004",
        "CVE-2015-0007",
        "CVE-2017-0005",
        "CVE-2020-0001",
    ]


def test_a_verified_cve_raises_the_confidence() -> None:
    reported = vulns(("CVE-2021-0002", 9.8, True), ("CVE-2020-0001", None, None))
    facts = only_address(host("a.example.com", ports=ports_result("a.example.com", vulns=reported)))
    assert one("CVE_OBSERVED", facts).confidence == "medium"


def test_cves_without_scores_are_still_reported() -> None:
    facts = only_address(
        host(
            "a.example.com",
            ports=ports_result("a.example.com", vulns=vulns(("CVE-2020-0001", None, None))),
        )
    )
    draft = one("CVE_OBSERVED", facts)
    assert draft.params["max_cvss"] is None and draft.params["top"] == ["CVE-2020-0001"]


def test_no_cves_no_finding() -> None:
    assert (
        fire(
            "CVE_OBSERVED",
            only_address(
                host(
                    "a.example.com",
                    ports=ports_result("a.example.com", ports=((22, "tcp", None, None),)),
                )
            ),
        )
        == []
    )


def test_two_addresses_two_sets_of_findings() -> None:
    a = host("a.example.com", ports=ports_result("a.example.com", ports=((22, "tcp", None, None),)))
    b = host(
        "b.example.com",
        ports=ports_result("b.example.com", address=OTHER, ports=((22, "tcp", None, None),)),
    )
    subjects = sorted(d.subject for ip in addresses(a, b) for d in fire("RISKY_PORT_EXPOSED", ip))
    assert subjects == [f"ip:{IP}:22", f"ip:{OTHER}:22"]


# ------------------------------------------------------------------------------ ranking


def ranked(
    known: dict[str, exploit_data.Enrichment], *pairs: tuple[str, float | None, bool | None]
) -> Any:
    """The CVE finding of an address whose CVEs the real check ranked with ``known``."""
    lookup = FakeExploits(known)
    outcome = ports_result("a.example.com", vulns=vulns(*pairs), exploits=lookup)
    return one("CVE_OBSERVED", only_address(host("a.example.com", ports=outcome)))


def enrich(kev: bool = False, epss: float | None = None, ransomware: bool = False) -> Any:
    return exploit_data.Enrichment(
        listed("CVE-2021-0002", ransomware=ransomware) if kev else None,
        scored(epss) if epss is not None else None,
    )


def test_a_cve_on_the_kev_list_makes_the_finding_high() -> None:
    draft = ranked(
        {"CVE-2021-0002": enrich(kev=True, epss=0.01)},
        ("CVE-2020-0001", 9.8, None),
        ("CVE-2021-0002", 5.0, None),
    )
    assert draft.severity == "high" and draft.confidence == "low"  # a lead, not a verified CVE
    assert draft.params["kev"] == ["CVE-2021-0002"] and draft.params["ransomware"] is None
    assert draft.params["top"][0] == "CVE-2021-0002"  # known exploited comes first
    assert draft.params["ranked_by"] == "kev_epss" and draft.params["exploit_stale"] is None


def test_kev_use_in_ransomware_campaigns_is_said_and_a_verified_cve_raises_the_confidence() -> None:
    draft = ranked(
        {"CVE-2021-0002": enrich(kev=True, ransomware=True)}, ("CVE-2021-0002", None, True)
    )
    assert draft.severity == "high" and draft.confidence == "medium"
    assert draft.params["ransomware"] is True


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (0.9999, "medium"),
        (0.5, "medium"),
        (0.4999, "low"),
        (0.1, "low"),
        (0.0999, "informational"),
        (0.0002, "informational"),
    ],
)
def test_the_epss_score_sets_the_severity_when_nothing_is_known_to_be_exploited(
    score: float, severity: str
) -> None:
    draft = ranked({"CVE-2020-0001": enrich(epss=score)}, ("CVE-2020-0001", 9.8, None))
    assert draft.severity == severity and draft.params["max_epss"] == score


def test_the_highest_epss_of_all_the_cves_counts() -> None:
    draft = ranked(
        {"CVE-2020-0001": enrich(epss=0.02), "CVE-2020-0002": enrich(epss=0.7)},
        ("CVE-2020-0001", 9.8, None),
        ("CVE-2020-0002", 3.1, None),
    )
    assert draft.severity == "medium" and draft.params["max_epss"] == 0.7
    assert draft.params["top"] == ["CVE-2020-0002", "CVE-2020-0001"]  # by exploitation, not CVSS


def test_without_exploitation_data_the_finding_stays_informational_and_says_it_is_not_ranked() -> (
    None
):
    lookup = FakeExploits(snapshot=exploit_data.Snapshot())
    outcome = ports_result(
        "a.example.com", vulns=vulns(("CVE-2020-0001", 9.8, None)), exploits=lookup
    )
    draft = one("CVE_OBSERVED", only_address(host("a.example.com", ports=outcome)))
    assert draft.severity == "informational"
    assert draft.params["ranked_by"] == "none" and draft.params["kev"] == []
    assert draft.params["max_epss"] is None


def test_data_that_is_out_of_date_is_said_so() -> None:
    lookup = FakeExploits(
        {"CVE-2020-0001": enrich(kev=True)},
        exploit_data.Snapshot("2026-09-01", "2026-09-01", stale=True),
    )
    outcome = ports_result(
        "a.example.com", vulns=vulns(("CVE-2020-0001", None, None)), exploits=lookup
    )
    draft = one("CVE_OBSERVED", only_address(host("a.example.com", ports=outcome)))
    assert draft.severity == "high" and draft.params["exploit_stale"] is True


def test_results_stored_before_exploitation_data_existed_still_work() -> None:
    """A finished scan from before this story has no kev/epss keys: the rule must not fail."""
    reported = vulns(("CVE-2021-0002", 9.8, None), ("CVE-2020-0001", 4.3, None))
    outcome = ports_result("a.example.com", vulns=reported)
    for entry in outcome.data["addresses"]:
        entry["facts"].pop("exploit_data", None)
        for vulnerability in entry["facts"]["vulnerabilities"]:
            vulnerability.pop("kev", None)
            vulnerability.pop("epss", None)
    draft = one("CVE_OBSERVED", only_address(host("a.example.com", ports=outcome)))
    assert draft.severity == "informational" and draft.params["ranked_by"] == "none"
    assert draft.params["max_cvss"] == 9.8


@pytest.mark.parametrize(
    ("early", "late"), [("a.example.com", "b.example.com"), ("b.example.com", "a.example.com")]
)
def test_an_address_is_judged_by_the_host_that_knew_most_about_its_cves(
    early: str, late: str
) -> None:
    """The data can be installed or updated while a scan runs. A host checked before that must not
    hide what a later one found, whichever of the two names comes first."""
    reported = vulns(("CVE-2021-0002", 9.8, None))
    before = ports_result(
        early, vulns=reported, exploits=FakeExploits(snapshot=exploit_data.Snapshot())
    )
    after = ports_result(
        late, vulns=reported, exploits=FakeExploits({"CVE-2021-0002": enrich(kev=True)})
    )
    address = only_address(host(early, ports=before), host(late, ports=after))
    draft = one("CVE_OBSERVED", address)
    assert draft.severity == "high" and draft.params["ranked_by"] == "kev_epss"
    assert sorted(draft.params["hosts"]) == ["a.example.com", "b.example.com"]  # both are named


def test_with_data_of_the_same_kind_the_newer_release_speaks_for_the_address() -> None:
    reported = vulns(("CVE-2021-0002", 9.8, None))
    older = ports_result(
        "a.example.com",
        vulns=reported,
        exploits=FakeExploits(snapshot=exploit_data.Snapshot("2026-10-04", "2026-10-04")),
    )
    newer = ports_result(
        "b.example.com",
        vulns=reported,
        exploits=FakeExploits(
            {"CVE-2021-0002": enrich(kev=True)}, exploit_data.Snapshot("2026-10-05", "2026-10-05")
        ),
    )
    draft = one(
        "CVE_OBSERVED",
        only_address(host("a.example.com", ports=older), host("b.example.com", ports=newer)),
    )
    assert draft.severity == "high"


def test_a_ranking_by_both_lists_beats_a_newer_one_by_a_single_list() -> None:
    reported = vulns(("CVE-2021-0002", 9.8, None))
    both = ports_result(
        "a.example.com",
        vulns=reported,
        exploits=FakeExploits(
            {"CVE-2021-0002": enrich(kev=True)}, exploit_data.Snapshot("2026-10-04", "2026-10-04")
        ),
    )
    one_list = ports_result(
        "b.example.com",
        vulns=reported,
        exploits=FakeExploits(snapshot=exploit_data.Snapshot(None, "2026-10-06")),
    )
    draft = one(
        "CVE_OBSERVED",
        only_address(host("a.example.com", ports=both), host("b.example.com", ports=one_list)),
    )
    assert draft.severity == "high" and draft.params["ranked_by"] == "kev_epss"


def test_shared_infrastructure_is_still_skipped_when_a_cve_is_known_exploited() -> None:
    lookup = FakeExploits({"CVE-2021-0002": enrich(kev=True)})
    outcome = ports_result(
        "cdn.example.com", vulns=vulns(("CVE-2021-0002", 9.8, None)), shared=True, exploits=lookup
    )
    assert fire("CVE_OBSERVED", only_address(host("cdn.example.com", ports=outcome))) == []
