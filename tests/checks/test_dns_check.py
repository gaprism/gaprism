"""The DNS check, against real dnspython answer objects and a scripted resolver (no network)."""

from __future__ import annotations

from typing import Any

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.reversename
import httpx

from app.checks.base import CheckContext, CheckOutcome
from app.checks.dns import MAX_RECORDS, MAX_TEXT, DnsCheck, _build_resolver, reverse_names

CONFIG: dict[str, Any] = {
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "DNS_TIMEOUT_SECONDS": 5.0,
}
TIMEOUT = dns.resolver.LifetimeTimeout(timeout=5, errors=[])


def rr(name: str, ttl: int, rdtype: str, rdata: str) -> str:
    """One zone-file line."""
    return f"{name}. {ttl} IN {rdtype} {rdata}"


def answer(qname: str, rdtype: str, *lines: str) -> dns.resolver.Answer:
    """A genuine ``dns.resolver.Answer`` parsed from zone-file lines (CNAME chains included)."""
    text = "\n".join(
        [
            "id 1",
            "opcode QUERY",
            "rcode NOERROR",
            "flags QR RD RA",
            ";QUESTION",
            f"{qname}. IN {rdtype}",
            ";ANSWER",
            *lines,
            ";AUTHORITY",
            ";ADDITIONAL",
        ]
    )
    return dns.resolver.Answer(
        dns.name.from_text(qname),
        dns.rdatatype.from_text(rdtype),
        dns.rdataclass.IN,
        dns.message.from_text(text),
    )


class ScriptedResolver:
    """Returns the scripted outcome for ``(name, type)``; anything else is "no such record"."""

    def __init__(self, script: dict[tuple[str, str], Any]) -> None:
        self.script = script
        self.calls: list[tuple[str, str]] = []

    def resolve(self, qname: str, rdtype: str, *, lifetime: float | None = None) -> Any:
        self.calls.append((qname, rdtype))
        outcome = self.script.get((qname, rdtype), dns.resolver.NoAnswer())
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def run(
    script: dict[tuple[str, str], Any], host: str = "example.com"
) -> tuple[CheckOutcome, ScriptedResolver]:
    resolver = ScriptedResolver(script)
    check = DnsCheck(resolver_factory=lambda _config: resolver)
    ctx = CheckContext(domain="example.com", hostname=host, config=CONFIG, http=httpx.Client())
    return check.run(ctx), resolver


# ------------------------------------------------------------------------------ the facts


def test_a_plain_host_reports_addresses_mail_name_servers_txt_and_caa() -> None:
    host = "example.com"
    outcome, _ = run(
        {
            (host, "A"): answer(
                host, "A", rr(host, 300, "A", "93.184.216.34"), rr(host, 300, "A", "93.184.216.35")
            ),
            (host, "AAAA"): answer(
                host, "AAAA", rr(host, 120, "AAAA", "2606:2800:220:1:248:1893:25c8:1946")
            ),
            (host, "MX"): answer(host, "MX", rr(host, 60, "MX", "10 Mail.Example.com.")),
            (host, "NS"): answer(
                host,
                "NS",
                rr(host, 86400, "NS", "a.iana-servers.net."),
                rr(host, 86400, "NS", "b.iana-servers.net."),
            ),
            (host, "TXT"): answer(host, "TXT", rr(host, 300, "TXT", '"v=spf1 -all" " more"')),
            (host, "CAA"): answer(host, "CAA", rr(host, 3600, "CAA", '0 issue "letsencrypt.org"')),
        }
    )

    assert outcome.status == "ok" and outcome.source == "dns:1.1.1.1,8.8.8.8"
    data = outcome.data
    assert data["addresses"] == [
        "93.184.216.34",
        "93.184.216.35",
        "2606:2800:220:1:248:1893:25c8:1946",
    ]
    assert data["a"][0] == {"ip": "93.184.216.34", "ttl": 300}
    assert data["aaaa"][0]["ttl"] == 120
    assert data["mx"] == [{"preference": 10, "host": "mail.example.com", "ttl": 60}]  # lower-cased
    assert [record["host"] for record in data["ns"]] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert data["txt"] == [{"value": "v=spf1 -all more", "ttl": 300}]  # strings joined
    assert data["caa"] == [{"flags": 0, "tag": "issue", "value": "letsencrypt.org", "ttl": 3600}]
    assert data["cname"] == [] and data["canonical_name"] == "example.com"
    assert data["blocked"] == [] and data["errors"] == {} and data["dangling_cname"] is False


def test_the_cname_chain_is_kept_in_order_with_its_ttls() -> None:
    www, edge = "www.example.com", "edge.cdn.example.net"
    outcome, _ = run(
        {
            (www, "CNAME"): answer(www, "CNAME", rr(www, 300, "CNAME", f"{edge}.")),
            (edge, "CNAME"): answer(edge, "CNAME", rr(edge, 120, "CNAME", "origin.example.net.")),
            (www, "A"): answer(
                www, "A", rr(www, 300, "CNAME", f"{edge}."), rr(edge, 60, "A", "93.184.216.34")
            ),
        },
        host="WWW.example.com.",  # case and the final dot do not matter
    )
    assert outcome.status == "ok"
    assert outcome.data["cname"] == [
        {"name": www, "target": edge, "ttl": 300},
        {"name": edge, "target": "origin.example.net", "ttl": 120},
    ]
    assert outcome.data["canonical_name"] == "origin.example.net"
    assert outcome.data["addresses"] == ["93.184.216.34"]


def test_a_cname_loop_is_reported_not_followed_forever() -> None:
    a, b = "a.example.com", "b.example.com"
    outcome, resolver = run(
        {
            (a, "CNAME"): answer(a, "CNAME", rr(a, 60, "CNAME", f"{b}.")),
            (b, "CNAME"): answer(b, "CNAME", rr(b, 60, "CNAME", f"{a}.")),
        },
        host=a,
    )
    assert outcome.status == "ok"  # the two records were collected
    assert outcome.data["errors"] == {"CNAME": "cname_loop"}
    assert len([call for call in resolver.calls if call[1] == "CNAME"]) == 2


# ------------------------------------------------------------------------------ screening


def test_private_and_loopback_answers_are_recorded_as_blocked_never_as_addresses() -> None:
    host = "intranet.example.com"
    outcome, _ = run(
        {
            (host, "A"): answer(
                host,
                "A",
                rr(host, 60, "A", "10.0.0.5"),
                rr(host, 60, "A", "127.0.0.1"),
                rr(host, 60, "A", "93.184.216.34"),
            ),
            (host, "AAAA"): answer(host, "AAAA", rr(host, 60, "AAAA", "fd00::1")),
        },
        host=host,
    )
    assert outcome.status == "ok"
    assert outcome.data["addresses"] == ["93.184.216.34"]
    assert outcome.data["blocked"] == [
        {"ip": "10.0.0.5", "reason": "private"},
        {"ip": "127.0.0.1", "reason": "loopback"},
        {"ip": "fd00::1", "reason": "private"},
    ]


def test_a_host_that_only_points_at_private_space_has_no_usable_address() -> None:
    host = "vpn.example.com"
    outcome, _ = run({(host, "A"): answer(host, "A", rr(host, 60, "A", "192.168.1.1"))}, host=host)
    assert outcome.status == "ok" and outcome.data["addresses"] == []
    assert outcome.data["blocked"] == [{"ip": "192.168.1.1", "reason": "private"}]


# ------------------------------------------------------------------------------ nothing there


def test_a_name_that_does_not_exist_is_no_data_after_one_query() -> None:
    host = "gone.example.com"
    outcome, resolver = run({(host, "CNAME"): dns.resolver.NXDOMAIN()}, host=host)
    assert (outcome.status, outcome.reason_code) == ("no_data", "nxdomain")
    assert outcome.data["nxdomain"] is True
    assert resolver.calls == [(host, "CNAME")]  # no further questions about nothing


def test_a_name_without_any_record_is_no_data_not_ok() -> None:
    outcome, _ = run({}, host="empty.example.com")
    assert (outcome.status, outcome.reason_code) == ("no_data", "no_records")
    assert outcome.data["addresses"] == []


def test_a_cname_to_a_name_that_does_not_exist_is_a_dangling_cname() -> None:
    old, bucket = "old.example.com", "bucket.s3.example.net"
    outcome, _ = run(
        {
            (old, "CNAME"): answer(old, "CNAME", rr(old, 300, "CNAME", f"{bucket}.")),
            (bucket, "CNAME"): dns.resolver.NXDOMAIN(),
            (old, "A"): dns.resolver.NXDOMAIN(),
            (old, "AAAA"): dns.resolver.NXDOMAIN(),
        },
        host=old,
    )
    assert outcome.status == "ok"
    assert outcome.data["dangling_cname"] is True
    assert outcome.data["canonical_name"] == bucket
    assert outcome.data["addresses"] == []


# ------------------------------------------------------------------------------ problems stay typed


def test_one_failing_record_type_is_reported_and_the_rest_is_kept() -> None:
    host = "example.com"
    outcome, _ = run(
        {
            (host, "A"): answer(host, "A", rr(host, 300, "A", "93.184.216.34")),
            (host, "TXT"): TIMEOUT,
            (host, "MX"): dns.resolver.NoNameservers(
                request=dns.message.make_query(host, "MX"), errors=[]
            ),
        }
    )
    assert outcome.status == "ok" and outcome.data["addresses"] == ["93.184.216.34"]
    assert outcome.data["errors"] == {"MX": "servfail", "TXT": "timeout"}
    assert outcome.data["txt"] == []  # empty because it failed: the error says so


def test_an_unreachable_resolver_stops_after_two_questions() -> None:
    outcome, resolver = run({("example.com", "CNAME"): TIMEOUT, ("example.com", "A"): TIMEOUT})
    assert (outcome.status, outcome.reason_code) == ("error", "timeout")
    assert len(resolver.calls) == 2  # not seven timeouts per host


def test_every_type_failing_is_an_error_not_an_empty_result() -> None:
    boom = OSError("network is unreachable")
    host = "example.com"
    outcome, _ = run({(host, rdtype): boom for rdtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA")})
    assert (outcome.status, outcome.reason_code) == ("error", "network_error")


# ------------------------------------------------------------------------------ bounds


def test_records_and_text_are_bounded() -> None:
    host = "example.com"
    many = [rr(host, 60, "TXT", f'"token-{n}"') for n in range(MAX_RECORDS + 10)]
    outcome, _ = run({(host, "TXT"): answer(host, "TXT", *many)})
    assert len(outcome.data["txt"]) == MAX_RECORDS and outcome.data["truncated"] == ["TXT"]

    chunks = " ".join(f'"{"y" * 250}"' for _ in range(10))  # 2500 characters in one record
    long, _ = run({(host, "TXT"): answer(host, "TXT", rr(host, 60, "TXT", chunks))})
    assert len(long.data["txt"][0]["value"]) == MAX_TEXT


def test_reverse_names_come_from_the_ptr_record_of_the_reversed_address() -> None:
    ptr = dns.reversename.from_address("93.184.216.34").to_text()  # ends in a dot
    ptr6 = dns.reversename.from_address("2606:2800:220:1::1").to_text()
    assert ptr.startswith("34.216.184.93.in-addr.arpa") and ptr6.endswith("ip6.arpa.")
    resolver = ScriptedResolver(
        {
            (ptr, "PTR"): answer(
                ptr.rstrip("."), "PTR", rr(ptr.rstrip("."), 300, "PTR", "Host.Example.com.")
            ),
            (ptr6, "PTR"): TIMEOUT,
        }
    )
    assert reverse_names(resolver, "93.184.216.34", 5.0) == (["host.example.com"], None)
    assert reverse_names(resolver, "2606:2800:220:1::1", 5.0) == ([], "timeout")
    assert reverse_names(resolver, "9.9.9.9", 5.0) == ([], None)  # no PTR record: nothing to say


def test_a_missing_hostname_is_an_error() -> None:
    check = DnsCheck(resolver_factory=lambda _config: ScriptedResolver({}))
    ctx = CheckContext(domain="example.com", hostname=None, config=CONFIG, http=httpx.Client())
    assert check.run(ctx).status == "error"


# ------------------------------------------------------------------------------ resolver setup


def test_a_resolver_is_built_once_per_configuration() -> None:
    built: list[dict[str, Any]] = []

    def factory(config: Any) -> ScriptedResolver:
        built.append(dict(config))
        return ScriptedResolver({})

    check = DnsCheck(resolver_factory=factory)
    for config in (CONFIG, CONFIG, {**CONFIG, "DNS_TIMEOUT_SECONDS": 9.0}):
        check.run(CheckContext("example.com", "example.com", config, httpx.Client()))
    assert len(built) == 2


def test_the_real_resolver_is_configured_from_settings() -> None:
    resolver = _build_resolver({"EGRESS_DNS_RESOLVERS": ["9.9.9.9"], "DNS_TIMEOUT_SECONDS": 4.0})
    assert isinstance(resolver, dns.resolver.Resolver)
    assert resolver.nameservers == ["9.9.9.9"]
    assert (resolver.timeout, resolver.lifetime) == (2.0, 4.0)
