"""Report calculations. Everything here works on plain dicts so it can be tested offline."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from typing import Any

Incident = dict[str, Any]


def ms_to_datetime(value: int | None) -> datetime | None:
    return None if value is None else datetime.fromtimestamp(value / 1000, tz=UTC)


def format_timestamp(value: int | None) -> str:
    moment = ms_to_datetime(value)
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else "N/A"


def format_timedelta(delta: timedelta) -> str:
    total = int(delta.total_seconds())
    sign = "-" if total < 0 else ""
    days, remainder = divmod(abs(total), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    clock = f"{hours:02}:{minutes:02}:{seconds:02}"
    return f"{sign}{days}d {clock}" if days else f"{sign}{clock}"


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())


def strip_html(value: str | None) -> str:
    """Reduce SOAR rich-text fields to plain text."""
    if not value:
        return "N/A"
    parser = _TextExtractor()
    parser.feed(value)
    return " ".join(parser.parts) or "N/A"


def name_matches(incident: Incident, patterns: Iterable[str]) -> bool:
    name = incident.get("name") or ""
    return any(pattern in name for pattern in patterns)


def split_values(raw: str | None) -> list[str]:
    return [item.strip() for item in (raw or "").split(",") if item.strip()]


# --------------------------------------------------------------------------- weekly report


def incident_type(name: str) -> str:
    """Extract the rule part of names like ``Prefix: Rule name - host``."""
    if ":" in name and "-" in name:
        return name[name.find(":") + 1 : name.rfind("-")].strip()
    return "Unknown"


@dataclass(frozen=True)
class WeeklyOptions:
    resolution_metrics: Sequence[str] = (
        "False-Positive",
        "Action Taken",
        "Known Activity",
        "Non-Issue",
    )
    false_positive_label: str = "False-Positive"
    highlighted_severities: Sequence[str] = ("Critical",)
    offense_count_exclude: Sequence[str] = ()
    name_counters: Sequence[tuple[str, str]] = ()
    customer_response_field: str = "customer_response"
    honeypot_ip_field: str | None = None
    firewall_ip_field: str | None = None
    firewall_flag_field: str | None = None
    proxy_domain_field: str | None = None


@dataclass
class WeeklyReport:
    period_start: datetime
    period_end: datetime
    summary: list[tuple[str, str]] = field(default_factory=list)
    automation: list[tuple[str, str]] = field(default_factory=list)
    top_types: list[tuple[str, int]] = field(default_factory=list)
    new_types: list[tuple[str, int]] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    by_severity: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def _incident_row(
    incident: Incident, options: WeeklyOptions, resolution_labels: dict[Any, str]
) -> dict[str, Any]:
    properties = incident.get("properties") or {}
    return {
        "Incident ID": incident.get("id"),
        "Name": incident.get("name") or "",
        "Created": format_timestamp(incident.get("create_date")),
        "Resolution": resolution_labels.get(incident.get("resolution_id"), "Open"),
        "Resolution Summary": strip_html(incident.get("resolution_summary")),
        "Customer Response": properties.get(options.customer_response_field) or "N/A",
    }


def build_weekly_report(
    reported: list[Incident],
    reported_baseline: list[Incident],
    all_incidents: list[Incident],
    resolution_labels: dict[Any, str],
    severity_labels: dict[Any, str],
    options: WeeklyOptions,
    period_start: datetime,
    period_end: datetime,
) -> WeeklyReport:
    """Build the weekly SOC report.

    ``reported`` holds the period's incidents that were reported to the customer,
    ``reported_baseline`` the same for the preceding baseline window (used to spot
    new incident types) and ``all_incidents`` every incident created in the period.
    """
    report = WeeklyReport(period_start=period_start, period_end=period_end)

    def resolution_of(incident: Incident) -> str | None:
        return resolution_labels.get(incident.get("resolution_id"))

    offense_count = sum(
        1 for i in all_incidents if not name_matches(i, options.offense_count_exclude)
    )
    reported_count = sum(
        1 for i in all_incidents if (i.get("properties") or {}).get("date_reported")
    )
    report.summary.append(("Offense Count / Incident Count", f"{offense_count} / {reported_count}"))
    for label in options.resolution_metrics:
        report.summary.append((label, str(sum(1 for i in reported if resolution_of(i) == label))))
    report.summary.append(
        ("No Response", str(sum(1 for i in reported if not i.get("resolution_id"))))
    )

    for label, pattern in options.name_counters:
        report.automation.append(
            (label, str(sum(1 for i in all_incidents if pattern in (i.get("name") or ""))))
        )
    if options.honeypot_ip_field:
        ips = {
            ip
            for i in all_incidents
            for ip in split_values((i.get("properties") or {}).get(options.honeypot_ip_field))
        }
        report.automation.append(("Honeypot IP blocking (unique IPs)", str(len(ips))))
    if options.firewall_ip_field:
        blocked = set()
        for i in all_incidents:
            properties = i.get("properties") or {}
            if options.firewall_flag_field and properties.get(options.firewall_flag_field) != "Yes":
                continue
            blocked.update(split_values(properties.get(options.firewall_ip_field)))
        report.automation.append(
            ("Firewall semi-automatic blocked IP addresses", ", ".join(sorted(blocked)) or "N/A")
        )
    if options.proxy_domain_field:
        domains = {
            d
            for i in all_incidents
            for d in split_values((i.get("properties") or {}).get(options.proxy_domain_field))
        }
        report.automation.append(
            ("Web proxy semi-automatic blocked domains", ", ".join(sorted(domains)) or "N/A")
        )

    current_types = Counter(incident_type(i.get("name") or "") for i in reported)
    baseline_types = Counter(incident_type(i.get("name") or "") for i in reported_baseline)
    report.top_types = current_types.most_common(5)
    report.new_types = [
        (name, count) for name, count in current_types.most_common() if name not in baseline_types
    ]

    report.false_positives = [
        _incident_row(i, options, resolution_labels)
        for i in reported
        if resolution_of(i) == options.false_positive_label
    ]
    for incident in reported:
        severity = severity_labels.get(incident.get("severity_code"))
        if severity in options.highlighted_severities:
            report.by_severity.setdefault(severity, []).append(
                _incident_row(incident, options, resolution_labels)
            )
    return report


# --------------------------------------------------------------------------- 24 hour offense summary


@dataclass
class OffenseRow:
    rule: str
    count: int = 0
    closed_by_soc: int = 0
    reported: int = 0
    no_action: int = 0


def rule_name(incident: Incident, fallback: str) -> str:
    description = incident.get("description") or ""
    if "categories:" in description:
        return strip_html(description.split("categories:", 1)[1])
    return fallback


def build_offense_summary(
    incidents: Iterable[Incident], exclude: Sequence[str], fallback_rule: str
) -> list[OffenseRow]:
    """Group incidents by detection rule and count what happened to them.

    * closed by SOC: closed without being reported to the customer
    * reported: escalated to the customer (``date_reported`` set)
    * no action: still active and not reported yet
    """
    rows: dict[str, OffenseRow] = {}
    for incident in incidents:
        if name_matches(incident, exclude):
            continue
        rule = rule_name(incident, fallback_rule)
        row = rows.setdefault(rule, OffenseRow(rule))
        reported = (incident.get("properties") or {}).get("date_reported") is not None
        status = incident.get("plan_status")
        row.count += 1
        row.reported += reported
        row.closed_by_soc += not reported and status == "C"
        row.no_action += not reported and status == "A"
    return sorted(rows.values(), key=lambda r: (-r.count, r.rule))


# --------------------------------------------------------------------------- log source health


def failing_log_sources(
    sources: Iterable[dict[str, Any]],
    now: datetime,
    stale_hours: int,
    exclude_names: Iterable[str] = (),
    ha_pairs: Iterable[tuple[str, str]] = (),
    excluded_group_ids: Iterable[int] = (),
) -> list[dict[str, Any]]:
    """Log sources in ERROR state that have been silent for at least ``stale_hours``.

    When only one member of an HA pair is failing the other one is still
    carrying the traffic, so that member is not reported.
    """
    excluded = {name.strip().lower() for name in exclude_names}
    threshold_ms = (now - timedelta(hours=stale_hours)).timestamp() * 1000
    candidates = [
        source
        for source in sources
        if (source.get("status") or {}).get("status") == "ERROR"
        and (source.get("name") or "").strip().lower() not in excluded
        and int(source.get("last_event_time") or 0) <= threshold_ms
    ]

    failing_names = {source.get("name") for source in candidates}
    covered_by_peer = set()
    for first, second in ha_pairs:
        if (first in failing_names) != (second in failing_names):
            covered_by_peer.add(first if first in failing_names else second)

    groups = set(excluded_group_ids)
    return [
        source
        for source in candidates
        if source.get("name") not in covered_by_peer
        and not groups.intersection(source.get("group_ids") or [])
    ]


def describe_log_sources(sources: Iterable[dict[str, Any]], type_names: dict[int, str]) -> str:
    """Serialise sources as ``name_type_lastEvent`` items separated by commas."""
    items = []
    for source in sources:
        type_name = type_names.get(source.get("type_id"), f"type {source.get('type_id')}")
        items.append(
            f"{source.get('name')}_{type_name}_{format_timestamp(source.get('last_event_time'))}"
        )
    return ",".join(items)


def log_source_incident(
    description: str, field_name: str, value: str, now: datetime, name: str
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "discovered_date": int(now.timestamp() * 1000),
        "properties": {field_name: value},
    }


# --------------------------------------------------------------------------- analyst SLA


@dataclass
class SlaDetail:
    analyst: str
    incident_id: Any
    incident_url: str
    response_time: timedelta
    exceeded: bool


@dataclass
class SlaSummary:
    analyst: str
    total: int
    exceeded: int
    average: timedelta


def build_sla_report(
    incidents: Iterable[Incident],
    analyst_field: str,
    reported_field: str,
    threshold: timedelta,
    now: datetime,
    incident_url,
) -> tuple[list[SlaSummary], list[SlaDetail]]:
    """Time from incident creation to customer notification, per analyst.

    Incidents that have not been reported yet are measured up to ``now``.
    """
    details: list[SlaDetail] = []
    for incident in incidents:
        created = ms_to_datetime(incident.get("create_date"))
        if created is None:
            continue
        properties = incident.get("properties") or {}
        reported = ms_to_datetime(properties.get(reported_field)) or now
        response = reported - created
        details.append(
            SlaDetail(
                analyst=str(properties.get(analyst_field) or "Unassigned"),
                incident_id=incident.get("id"),
                incident_url=incident_url(incident),
                response_time=response,
                exceeded=response > threshold,
            )
        )

    details.sort(key=lambda d: (d.analyst, not d.exceeded, str(d.incident_id)))
    summaries = []
    for analyst in sorted({d.analyst for d in details}):
        own = [d for d in details if d.analyst == analyst]
        summaries.append(
            SlaSummary(
                analyst=analyst,
                total=len(own),
                exceeded=sum(d.exceeded for d in own),
                average=sum((d.response_time for d in own), timedelta()) / len(own),
            )
        )
    return summaries, details
