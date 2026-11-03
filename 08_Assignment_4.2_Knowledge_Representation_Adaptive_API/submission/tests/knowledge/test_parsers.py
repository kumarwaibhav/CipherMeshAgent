"""Parsers on saved real payloads, synthetic edge cases and malformed / hostile input.

Author: Kumar Waibhav Akshat (RA2212704010027)
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from ciphermesh.knowledge.feeds import (AiIncidentConnector, AwsHealthConnector, AzureStatusConnector,
                                        CisaKevConnector, FxRateConnector, GcpStatusConnector, ParseError,
                                        UnsafeXMLError, parse_rss, parse_xml)
from ciphermesh.knowledge.feeds.normalize import classify_impact, clean_text, parse_date

from .conftest import REPLAY_AS_OF, WHATIF

STAMP = "2026-10-30T23:00:00+00:00"
NOW = datetime(2026, 10, 30, 23, 0, tzinfo=timezone.utc)


# ----------------------------------------------------------------------------- normaliser
@pytest.mark.parametrize("raw, code", [
    ("Iowa (us-central1)", "us-central1"), ("us-central1-b", "us-central1"), ("AP-SOUTH-1", "ap-south-1"),
    ("Asia Pacific (Mumbai)", "ap-south-1"), ("Central India", "centralindia"), ("Oregon", "us-west-2"),
    ("London (europe-west2)", "europe-west2"), ("nowhere-land", None), ("", None)])
def test_region_normalisation(norm, raw, code):
    assert norm.region(raw) == code


def test_free_text_extraction_of_regions_and_services(norm):
    text = "Customers using Azure AI Services in Central India and Vertex Gemini API in us-central1-a saw errors"
    assert {"centralindia", "us-central1"} <= norm.find_regions(text)
    assert norm.find_providers(text) == {"azure-ai", "gcp-vertex"}
    assert norm.find_providers("Amazon Bedrock latency") == {"aws-bedrock"}


def test_clean_text_and_impact_classes():
    assert clean_text("<p>Hello&nbsp;<b>world</b></p>\n\n x") == "Hello world x"
    assert classify_impact("customers may be unable to access deployments") == "outage"
    assert classify_impact("increased error rates for uploads") == "degraded"
    assert classify_impact("The issue has been mitigated") == "resolved"
    assert classify_impact("Scheduled maintenance notice") == "advisory"


def test_date_parsing_variants():
    assert parse_date("Fri, 27 Feb 2026 12:20:00 Z").hour == 12
    assert parse_date("2026-02-27T12:37:00+00:00").minute == 37
    assert parse_date("1793323718").year == 2026
    assert parse_date("yesterday") is None and parse_date("") is None


# ----------------------------------------------------------------------------- GCP
def test_gcp_real_sample_today_is_operational(graph, norm, fix):
    r = GcpStatusConnector(graph, norm).parse((fix / "gcp_incidents_real_sample.json").read_bytes(), STAMP, NOW)
    assert r.items_seen == 3 and r.signals["provider_status"]["gcp-vertex"]["status"] == "operational"
    assert r.signals["recent_total"] == 2           # europe-west2 and the us-central1 storage incident


def test_gcp_replay_at_incident_time_marks_vertex_degraded(graph, norm, fix):
    r = GcpStatusConnector(graph, norm).parse((fix / "gcp_incidents_real_sample.json").read_bytes(), STAMP,
                                              REPLAY_AS_OF)
    st = r.signals["provider_status"]["gcp-vertex"]
    assert st["status"] == "degraded" and st["confidence"] == 0.9 and st["incidents"]
    assert any(f.predicate == "cm:affectsRegion" and f.obj == "cm:region/us-central1" for f in r.facts)
    status_fact = [f for f in r.facts if f.predicate == "cm:hasStatus"][0]
    assert status_fact.obj == "cm:status/degraded" and status_fact.source == "cm:feed/gcp-status"


def test_gcp_active_outage_only_counts_for_the_provider_region(graph, norm):
    base = {"begin": "2026-10-30T20:00:00+00:00", "status_impact": "SERVICE_OUTAGE", "service_name": "Vertex AI",
            "affected_products": [{"title": "Vertex AI Online Prediction"}], "external_desc": "Vertex AI outage"}
    elsewhere = dict(base, id="TEST-1", currently_affected_locations=[{"id": "europe-west4", "title": "x"}])
    here = dict(base, id="TEST-2", currently_affected_locations=[{"id": "us-central1", "title": "Iowa (us-central1)"}])
    conn = GcpStatusConnector(graph, norm)
    assert conn.parse(json.dumps([elsewhere]).encode(), STAMP, NOW).signals["provider_status"]["gcp-vertex"][
        "status"] == "operational"
    assert conn.parse(json.dumps([elsewhere, here]).encode(), STAMP, NOW).signals["provider_status"]["gcp-vertex"][
        "status"] == "outage"


def test_gcp_unstructured_fallback_reads_regions_from_prose(graph, norm):
    inc = {"id": "TEST-3", "begin": "2026-10-30T20:00:00+00:00", "status_impact": "SERVICE_INFORMATION",
           "affected_products": [{"title": "Vertex Gemini API"}],
           "external_desc": "Elevated latency for Vertex Gemini API requests served from us-central1."}
    r = GcpStatusConnector(graph, norm).parse(json.dumps([inc]).encode(), STAMP, NOW)
    assert r.signals["provider_status"]["gcp-vertex"]["status"] == "degraded"


@pytest.mark.parametrize("payload, error", [(b'{"incidents": [', ParseError), (b'{"a": 1}', ParseError),
                                            (b"\x00\x01garbage", ParseError)])
def test_gcp_malformed_payloads_raise_parse_error(graph, norm, payload, error):
    with pytest.raises(error):
        GcpStatusConnector(graph, norm).parse(payload, STAMP, NOW)


def test_gcp_bad_records_are_skipped_with_warnings(graph, norm):
    r = GcpStatusConnector(graph, norm).parse(json.dumps([1, {"id": "x"}, {"begin": "not a date"}]).encode(),
                                              STAMP, NOW)
    assert r.items_seen == 3 and len(r.warnings) == 3
    assert r.signals["provider_status"]["gcp-vertex"]["status"] == "operational"


# ----------------------------------------------------------------------------- Azure
def test_azure_empty_real_feed_is_operational(graph, norm, fix):
    r = AzureStatusConnector(graph, norm).parse((fix / "azure_status_empty_real.xml").read_bytes(), STAMP, NOW)
    assert r.items_seen == 0 and r.signals["provider_status"]["azure-ai"]["status"] == "operational"


def test_azure_whatif_fixture_extracts_outage_in_central_india(graph, norm):
    r = AzureStatusConnector(graph, norm).parse(WHATIF.read_bytes(), STAMP, REPLAY_AS_OF)
    st = r.signals["provider_status"]["azure-ai"]
    assert st["status"] == "outage" and st["confidence"] == 0.85
    assert r.items_seen == 2 and r.items_relevant == 1          # the West Europe storage item is not relevant
    assert "westeurope" in r.signals["regions_seen"]


def test_azure_resolved_item_counts_as_recent_not_active(graph, norm):
    xml = (b'<?xml version="1.0"?><rss version="2.0"><channel><title>Azure Status</title><item>'
           b'<title>Azure AI Foundry - Central India - Mitigated</title>'
           b'<description>&lt;p&gt;The issue has been mitigated.&lt;/p&gt;</description>'
           b'<pubDate>Fri, 30 Oct 2026 20:00:00 Z</pubDate></item></channel></rss>')
    r = AzureStatusConnector(graph, norm).parse(xml, STAMP, NOW)
    assert r.signals["provider_status"]["azure-ai"]["status"] == "operational"
    assert r.signals["recent_incidents"]["azure-ai"] == 1


def test_azure_broad_scope_item_applies_with_lower_confidence(graph, norm):
    xml = (b'<rss version="2.0"><channel><title>t</title><item><title>Azure AI Foundry - Multiple Regions</title>'
           b'<description>Customers may experience intermittent errors in multiple regions.</description>'
           b'<pubDate>Fri, 30 Oct 2026 21:00:00 Z</pubDate></item></channel></rss>')
    st = AzureStatusConnector(graph, norm).parse(xml, STAMP, NOW).signals["provider_status"]["azure-ai"]
    assert st["status"] == "degraded" and st["confidence"] == 0.6


BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<rss><channel><title>&lol2;</title></channel></rss>"""
XXE = b"""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss>&x;</rss>"""


@pytest.mark.parametrize("payload", [BILLION_LAUGHS, XXE, b"<!doctype html><html></html>"])
def test_dtd_and_entities_are_refused(payload, graph, norm):
    with pytest.raises(UnsafeXMLError):
        parse_xml(payload)
    with pytest.raises(UnsafeXMLError):
        AzureStatusConnector(graph, norm).parse(payload, STAMP, NOW)


def test_malformed_and_oversized_xml(monkeypatch):
    with pytest.raises(ValueError):
        parse_rss(b"<rss><channel><item><title>unclosed</channel></rss>")
    import ciphermesh.knowledge.feeds.safe_xml as sx
    monkeypatch.setattr(sx, "MAX_XML_BYTES", 10)
    with pytest.raises(UnsafeXMLError):
        sx.parse_xml(b"<rss>0123456789</rss>")


def test_atom_entries_are_supported():
    atom = (b'<feed xmlns="http://www.w3.org/2005/Atom"><title>x</title><entry><title>A</title>'
            b'<summary>B</summary><id>1</id><updated>2026-10-30T00:00:00Z</updated></entry></feed>')
    _t, items = parse_rss(atom)
    assert items[0].title == "A" and items[0].description == "B"


# ----------------------------------------------------------------------------- AWS
def test_aws_real_utf16_sample_parses_and_ignores_other_regions(graph, norm, fix):
    body = (fix / "aws_currentevents_real_sample.json").read_bytes()
    assert body[:2] in (b"\xff\xfe", b"\xfe\xff")
    r = AwsHealthConnector(graph, norm).parse(body, STAMP, NOW)
    assert r.items_seen == 3 and r.items_relevant == 0
    assert {"me-central-1", "us-west-2"} <= set(r.signals["regions_seen"])
    assert r.signals["provider_status"]["aws-bedrock"]["status"] == "operational"


def _aws_event(service, status_codes, end=None, top="1"):
    ts = int(NOW.timestamp()) - 3600
    return {"date": str(ts), "arn": f"arn:aws:health:x::event/{service}", "region_name": "Mumbai", "status": top,
            "service": service, "service_name": "Amazon Bedrock" if "bedrock" in service else "Multiple services",
            "summary": "Increased error rates",
            "event_log": [{"summary": "Increased error rates", "message": "We are investigating increased errors.",
                           "status": s, "timestamp": ts + i} for i, s in enumerate(status_codes)],
            **({"end_time": str(end)} if end else {})}


def test_aws_bedrock_in_mumbai_maps_status_codes(graph, norm):
    conn = AwsHealthConnector(graph, norm)
    deg = conn.parse(json.dumps([_aws_event("bedrock-ap-south-1", [1, 2])]).encode("utf-8"), STAMP, NOW)
    assert deg.signals["provider_status"]["aws-bedrock"]["status"] == "degraded"
    out = conn.parse(json.dumps([_aws_event("multipleservices-ap-south-1", [3])]).encode("utf-16"), STAMP, NOW)
    st = out.signals["provider_status"]["aws-bedrock"]
    assert st["status"] == "outage" and st["confidence"] == 0.7
    other = conn.parse(json.dumps([_aws_event("bedrock-us-east-1", [3])]).encode(), STAMP, NOW)
    assert other.signals["provider_status"]["aws-bedrock"]["status"] == "operational"


def test_aws_resolved_and_empty_bodies(graph, norm):
    conn = AwsHealthConnector(graph, norm)
    res = conn.parse(json.dumps([_aws_event("bedrock-ap-south-1", [2], top="0")]).encode(), STAMP, NOW)
    assert res.signals["provider_status"]["aws-bedrock"]["status"] == "operational"
    assert res.signals["recent_incidents"]["aws-bedrock"] == 1
    assert conn.parse(b"", STAMP, NOW).items_seen == 0
    assert conn.parse(b"[]", STAMP, NOW).items_seen == 0
    with pytest.raises(ParseError):
        conn.parse(b'"just a string"', STAMP, NOW)


# ----------------------------------------------------------------------------- CISA KEV
def _kev(entries):
    return json.dumps({"catalogVersion": "test", "count": len(entries), "vulnerabilities": entries}).encode()


def _entry(days_ago, vendor="Acme", product="Widget", ransomware="Unknown", desc="Bug"):
    d = (NOW.date() - timedelta(days=days_ago)).isoformat()
    return {"cveID": f"CVE-2026-{days_ago:05d}{vendor[:2]}", "vendorProject": vendor, "product": product,
            "vulnerabilityName": f"{vendor} {product} bug", "dateAdded": d, "shortDescription": desc,
            "knownRansomwareCampaignUse": ransomware}


def test_kev_ratio_baseline_and_relevant_vendor_matching(graph):
    old = [_entry(30 + i * 3) for i in range(120)]         # about 10 per 30-day window in the past year
    recent = [_entry(i) for i in range(1, 21)] + [_entry(2, "Microsoft", "Windows"), _entry(3, "Linux", "Kernel"),
                                                  _entry(4, "Google", "Chromium", "Known")]
    r = CisaKevConnector(graph).parse(_kev(old + recent), STAMP, NOW)
    s = r.signals
    assert s["recent"] == 23 and s["baseline_monthly_median"] == 10.0 and s["ratio"] == 2.3
    assert s["relevant_hits"] == 3 and s["ransomware_hits"] == 1
    assert {f.obj for f in r.facts if f.predicate == "cm:affectsVendor"} == {
        "cm:vendor/microsoft", "cm:vendor/linux", "cm:vendor/google"}


def test_kev_ai_ml_detection_and_time_travel(graph):
    entries = [_entry(5, "Langflow", "Langflow"), _entry(6, "Acme", "Portal", desc="Remote code execution in AI agent"),
               _entry(400, "Ollama", "Ollama")]
    r = CisaKevConnector(graph).parse(_kev(entries), STAMP, NOW)
    assert r.signals["ai_ml_hits"] == 2 and r.signals["relevant_hits"] == 1
    past = CisaKevConnector(graph).parse(_kev(entries), STAMP, NOW - timedelta(days=398))
    assert past.signals["recent"] == 1 and past.signals["ai_ml_hits"] == 1        # future entries are invisible


def test_kev_malformed(graph):
    with pytest.raises(ParseError):
        CisaKevConnector(graph).parse(b'{"vulnerabilities": "nope"}', STAMP, NOW)
    r = CisaKevConnector(graph).parse(_kev([{"dateAdded": "31/12/2026"}, "x"]), STAMP, NOW)
    assert len(r.warnings) == 2 and r.signals["recent"] == 0


# ----------------------------------------------------------------------------- FX
def test_fx_real_sample(fix):
    r = FxRateConnector().parse((fix / "fx_usd_inr_real.json").read_bytes(), STAMP)
    assert r.signals["rate"] == 94.95 and r.signals["rate_date"] == "2026-10-30"
    assert r.facts[0].subject == "cm:fxrate/USD-INR" and r.facts[0].predicate == "cm:rateValue"


@pytest.mark.parametrize("payload", [b'{"base":"USD","rates":{"INR":"abc"}}', b'{"base":"USD","rates":{"INR":5000}}',
                                     b'{"base":"EUR","rates":{"INR":90}}', b'{"base":"USD"}', b"[1,2]",
                                     b'{"base":"USD","rates":{"INR":NaN}}'])
def test_fx_rejects_corrupt_values(payload):
    with pytest.raises(ParseError):
        FxRateConnector().parse(payload, STAMP)


def test_fx_amount_scaling_and_missing_date():
    r = FxRateConnector().parse(b'{"amount":10,"base":"USD","rates":{"INR":949.5}}', STAMP)
    assert r.signals["rate"] == 94.95 and r.warnings


# ----------------------------------------------------------------------------- AI Incident Database
MARKER = "Zorvane Clinic"            # invented name inside the synthetic fixture


def test_aiid_synthetic_sample_keyword_classes_and_rate(graph, fix):
    body = (fix / "aiid_rss_synthetic_sample.xml").read_bytes()
    r = AiIncidentConnector(graph).parse(body, STAMP, NOW)
    s = r.signals
    assert r.items_seen == 10 and s["items_in_window"] == 10
    assert (s["privacy_incidents"], s["intrusion_incidents"]) == (2, 2)
    assert s["covered_days"] == pytest.approx(6.96, abs=0.01)          # oldest item 24 Oct -> as_of 30 Oct 23:00
    assert s["privacy_per_day"] == pytest.approx(2 / s["covered_days"], abs=1e-3)
    stored = json.dumps([[f.subject, f.predicate, str(f.obj), f.evidence] for f in r.facts] + [s])
    assert MARKER in body.decode() and MARKER not in stored               # no report text is kept
    old = AiIncidentConnector(graph).parse(body, STAMP, datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert old.signals["items_in_window"] == 0 and old.signals["privacy_per_day"] == 0


def test_kev_vendor_match_is_exact_or_prefix(graph):
    conn = CisaKevConnector(graph)
    assert conn.vendor_of("Microsoft") == "cm:vendor/microsoft"
    assert conn.vendor_of("Linux") == "cm:vendor/linux"
    assert conn.vendor_of("Googleplex Fake") is None


def test_aiid_derivative_is_text_free_and_reproduces_counts(graph, fix):
    conn = AiIncidentConnector(graph)
    body = (fix / "aiid_rss_synthetic_sample.xml").read_bytes()
    derived = conn.derivative(body)
    assert MARKER.encode() not in derived and b"<description>" in derived[:300]
    a, b = conn.parse(body, STAMP, NOW).signals, conn.parse(derived, STAMP, NOW).signals
    assert a == b


@pytest.mark.parametrize("conn_cls, fixture, as_of", [
    ("gcp", "gcp_incidents_real_sample.json", REPLAY_AS_OF), ("gcp", "gcp_incidents_real_sample.json", NOW),
    ("aws", "aws_currentevents_real_sample.json", NOW), ("azure", None, REPLAY_AS_OF)])
def test_status_derivatives_drop_prose_and_reproduce_signals(graph, norm, fix, conn_cls, fixture, as_of):
    conn = {"gcp": GcpStatusConnector, "aws": AwsHealthConnector, "azure": AzureStatusConnector}[conn_cls](graph, norm)
    body = WHATIF.read_bytes() if fixture is None else (fix / fixture).read_bytes()
    derived = conn.derivative(body)
    for prose in (b"customers experienced", b"Impact Statement", b"we experienced", b"Engineers are investigating"):
        assert prose not in derived
    a, b = conn.parse(body, STAMP, as_of), conn.parse(derived, STAMP, as_of)
    assert a.signals == b.signals
    assert sorted((f.subject, f.predicate, str(f.obj)) for f in a.facts) == \
        sorted((f.subject, f.predicate, str(f.obj)) for f in b.facts)


def test_kev_derivative_keeps_flags_not_descriptions(graph):
    entries = [_entry(5, "Langflow", "Langflow"), _entry(6, "Acme", "Portal", desc="Remote code execution in AI agent"),
               _entry(7, "Microsoft", "Windows", "Known")]
    conn = CisaKevConnector(graph)
    derived = conn.derivative(_kev(entries))
    assert b"Remote code execution" not in derived and b"vulnerabilityName" not in derived
    assert conn.parse(_kev(entries), STAMP, NOW).signals == conn.parse(derived, STAMP, NOW).signals


def test_status_and_kev_labels_are_structured_not_feed_prose(graph, norm, fix):
    r = GcpStatusConnector(graph, norm).parse((fix / "gcp_incidents_real_sample.json").read_bytes(), STAMP,
                                              REPLAY_AS_OF)
    texts = [str(f.obj) for f in r.facts] + [f.evidence for f in r.facts] + [json.dumps(r.signals)]
    assert not any("customers experienced" in t for t in texts)
    assert any(t.startswith("GCP incident ") for t in texts)
    k = CisaKevConnector(graph).parse(_kev([_entry(2, "Microsoft", "Windows")]), STAMP, NOW)
    assert [f.obj for f in k.facts if f.predicate == "rdfs:label"] == ["CVE-2026-00002Mi (Microsoft Windows)"]
