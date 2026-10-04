from datetime import UTC, datetime, timedelta

from soar_periodic_reports import analytics
from soar_periodic_reports.analytics import WeeklyOptions

NOW = datetime(2025, 3, 10, 9, 0, tzinfo=UTC)
HOUR_MS = 3600 * 1000


def ms(hours_ago: float) -> int:
    return int((NOW - timedelta(hours=hours_ago)).timestamp() * 1000)


RESOLUTIONS = {1: "False-Positive", 2: "Action Taken", 3: "Known Activity", 4: "Non-Issue"}
SEVERITIES = {10: "Low", 20: "Critical"}


def inc(id_, name, resolution=None, severity=10, reported=True, **props):
    return {
        "id": id_,
        "name": name,
        "create_date": ms(10),
        "resolution_id": resolution,
        "severity_code": severity,
        "resolution_summary": "<p>Checked <b>proxy</b> logs</p>",
        "properties": {"date_reported": ms(9) if reported else None, **props},
    }


def test_incident_type_extraction():
    assert analytics.incident_type("SIEM: Brute Force Login - 10423") == "Brute Force Login"
    assert analytics.incident_type("No separator here") == "Unknown"


def test_strip_html():
    assert analytics.strip_html("<div>Blocked <b>at</b> firewall</div>") == "Blocked at firewall"
    assert analytics.strip_html(None) == "N/A"


def test_weekly_report():
    reported = [
        inc(1, "SIEM: Brute Force - a", resolution=1, customer_response="Expected"),
        inc(2, "SIEM: Brute Force - b", resolution=2, severity=20),
        inc(3, "SIEM: New Rule - c"),
    ]
    baseline = [inc(9, "SIEM: Brute Force - z", resolution=2)]
    all_incidents = [
        *reported,
        inc(4, "AUT - SIEM: Auto block - d", reported=False, honeypot="198.51.100.1, 198.51.100.2"),
        inc(
            5,
            "Canary hit",
            reported=False,
            honeypot="198.51.100.1",
            fw_ip="203.0.113.7",
            fw_flag="Yes",
        ),
        inc(
            6,
            "SIEM: Proxy - e",
            reported=False,
            fw_ip="203.0.113.8",
            fw_flag="No",
            proxy="bad.example",
        ),
    ]
    options = WeeklyOptions(
        resolution_metrics=["False-Positive", "Action Taken"],
        offense_count_exclude=["AUT -", "Canary"],
        name_counters=[("Rule based auto block", "AUT -")],
        honeypot_ip_field="honeypot",
        firewall_ip_field="fw_ip",
        firewall_flag_field="fw_flag",
        proxy_domain_field="proxy",
    )
    report = analytics.build_weekly_report(
        reported,
        baseline,
        all_incidents,
        RESOLUTIONS,
        SEVERITIES,
        options,
        NOW - timedelta(days=7),
        NOW,
    )

    assert report.summary == [
        ("Offense Count / Incident Count", "4 / 3"),
        ("False-Positive", "1"),
        ("Action Taken", "1"),
        ("No Response", "1"),
    ]
    assert report.automation == [
        ("Rule based auto block", "1"),
        ("Honeypot IP blocking (unique IPs)", "2"),
        ("Firewall semi-automatic blocked IP addresses", "203.0.113.7"),
        ("Web proxy semi-automatic blocked domains", "bad.example"),
    ]
    assert report.top_types == [("Brute Force", 2), ("New Rule", 1)]
    assert report.new_types == [("New Rule", 1)]
    assert [row["Incident ID"] for row in report.false_positives] == [1]
    assert report.false_positives[0]["Resolution Summary"] == "Checked proxy logs"
    assert report.false_positives[0]["Customer Response"] == "Expected"
    assert list(report.by_severity) == ["Critical"]
    assert report.by_severity["Critical"][0]["Resolution"] == "Action Taken"


def test_offense_summary_groups_by_rule():
    def offense(rule, status, reported, name="Offense"):
        return {
            "name": name,
            "plan_status": status,
            "description": f"<div>Offense details categories: {rule}</div>" if rule else None,
            "properties": {"date_reported": 1 if reported else None},
        }

    rows = analytics.build_offense_summary(
        [
            offense("Brute Force", "C", False),
            offense("Brute Force", "A", False),
            offense("Brute Force", "C", True),
            offense("Malware", "A", True),
            offense(None, "C", False),
            offense("Noise", "C", False, name="Log Source Check"),
        ],
        exclude=["Log Source Check"],
        fallback_rule="Uncategorized",
    )
    summary = [(r.rule, r.count, r.closed_by_soc, r.reported, r.no_action) for r in rows]
    assert summary == [
        ("Brute Force", 3, 1, 1, 1),
        ("Malware", 1, 0, 1, 0),
        ("Uncategorized", 1, 1, 0, 0),
    ]


def source(name, hours_silent, status="ERROR", groups=(), type_id=1):
    return {
        "name": name,
        "type_id": type_id,
        "status": {"status": status},
        "last_event_time": ms(hours_silent),
        "group_ids": list(groups),
    }


def test_failing_log_sources():
    sources = [
        source("fw-a", 72),
        source("fw-b", 1, status="SUCCESS"),
        source("lb-a", 72),
        source("lb-b", 72),
        source("db01", 50),
        source("recent", 10),
        source("lab", 72, groups=[99]),
        source("Excluded-Host", 72),
    ]
    failing = analytics.failing_log_sources(
        sources,
        now=NOW,
        stale_hours=48,
        exclude_names=["excluded-host"],
        ha_pairs=[("fw-a", "fw-b"), ("lb-a", "lb-b")],
        excluded_group_ids=[99],
    )
    assert [s["name"] for s in failing] == ["lb-a", "lb-b", "db01"]
    text = analytics.describe_log_sources(failing[:1], {1: "Firewall"})
    assert text.startswith("lb-a_Firewall_2025-03-07 09:00:00")


def test_sla_report():
    incidents = [
        {
            "id": 1,
            "org_id": 201,
            "create_date": ms(5),
            "properties": {"analyst": "alice", "reported_date": ms(4.5)},
        },
        {
            "id": 2,
            "org_id": 201,
            "create_date": ms(5),
            "properties": {"analyst": "alice", "reported_date": ms(1)},
        },
        {"id": 3, "org_id": 201, "create_date": ms(1), "properties": {"analyst": None}},
    ]
    summaries, details = analytics.build_sla_report(
        incidents,
        "analyst",
        "reported_date",
        timedelta(minutes=120),
        NOW,
        lambda i: f"https://soar/#incidents/{i['id']}",
    )
    assert [(s.analyst, s.total, s.exceeded) for s in summaries] == [
        ("Unassigned", 1, 0),
        ("alice", 2, 1),
    ]
    alice = summaries[1]
    assert alice.average == timedelta(hours=2, minutes=15)
    assert [(d.analyst, d.incident_id, d.exceeded) for d in details] == [
        ("Unassigned", 3, False),
        ("alice", 2, True),
        ("alice", 1, False),
    ]


def test_format_timedelta():
    assert analytics.format_timedelta(timedelta(hours=2, minutes=3, seconds=4)) == "02:03:04"
    assert analytics.format_timedelta(timedelta(days=1, minutes=1)) == "1d 00:01:00"
