"""HTML rendering for mail bodies (inline styles only, mail clients ignore most CSS)."""

from __future__ import annotations

import traceback
from collections.abc import Iterable, Sequence
from datetime import datetime
from html import escape
from typing import Any

from .analytics import OffenseRow, WeeklyReport

FONT = "font-family:Calibri, Arial, sans-serif;"
TABLE = "border-collapse:collapse; width:100%; margin-bottom:18px;"
TH = f"{FONT} border:1px solid #cccccc; padding:8px; text-align:left; background-color:#41729f; color:#ffffff;"
TD = f"{FONT} border:1px solid #cccccc; padding:8px; text-align:left; vertical-align:top;"
H2 = f"{FONT} color:#274472; margin:22px 0 8px 0;"


def _cell(value: Any) -> str:
    return escape("" if value is None else str(value))


def table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    head = "".join(f"<th style='{TH}'>{_cell(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td style='{TD}'>{_cell(v)}</td>" for v in row) + "</tr>" for row in rows
    )
    if not body:
        body = f"<tr><td style='{TD}' colspan='{len(headers)}'>No records</td></tr>"
    return f"<table style='{TABLE}'><tr>{head}</tr>{body}</table>"


def _records_table(records: list[dict[str, Any]]) -> str:
    if not records:
        return table(["Result"], [])
    headers = list(records[0].keys())
    return table(headers, ([record.get(h) for h in headers] for record in records))


def _document(title: str, body: str) -> str:
    return (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{escape(title)}</title></head>"
        f"<body style='{FONT} color:#1b2a38; margin:16px;'>{body}</body></html>"
    )


def render_weekly(report: WeeklyReport) -> str:
    period = f"{report.period_start:%Y-%m-%d %H:%M} to {report.period_end:%Y-%m-%d %H:%M} UTC"
    parts = [
        f"<h1 style='{FONT} color:#274472;'>Weekly SOC Report</h1>",
        f"<p style='{FONT} color:#5b6b79;'>{escape(period)}</p>",
        f"<h2 style='{H2}'>Summary</h2>",
        table(["SOC Operation Metric", "Count"], report.summary),
    ]
    if report.automation:
        parts += [
            f"<h2 style='{H2}'>Automation Metrics</h2>",
            table(["Automation Metric", "Count"], report.automation),
        ]
    parts += [
        f"<h2 style='{H2}'>Top 5 Incident Types</h2>",
        table(["Incident Type", "Count"], report.top_types),
        f"<h2 style='{H2}'>New Incident Types (not seen in the baseline period)</h2>",
        table(["Incident Type", "Count"], report.new_types),
        f"<h2 style='{H2}'>Incidents Closed as False Positive</h2>",
        _records_table(report.false_positives),
    ]
    for severity, records in report.by_severity.items():
        parts += [f"<h2 style='{H2}'>Severity: {escape(severity)}</h2>", _records_table(records)]
    return _document("Weekly SOC Report", "".join(parts))


# Column colours of the 24 hour summary: header colour, cell colour.
OFFENSE_COLUMNS = (
    ("Count", "#137cec", "#4296f0"),
    ("Closed by SOC", "#687f97", "#8699ac"),
    ("Reported", "#df2a20", "#e5554d"),
    ("No Action", "#c9c516", "#ece946"),
)


def render_offense_summary(rows: list[OffenseRow], hours: int) -> str:
    totals = (
        sum(r.count for r in rows),
        sum(r.closed_by_soc for r in rows),
        sum(r.reported for r in rows),
        sum(r.no_action for r in rows),
    )
    title_cell = f"{FONT} background-color:#274472; color:#ffffff; font-weight:bold; text-align:center; padding:9px;"
    header = f"<th style='{TH} width:50%;'>Offense Name</th>" + "".join(
        f"<th style='{TH} width:12.5%; text-align:center; background-color:{head};'>{name} - {total}</th>"
        for (name, head, _), total in zip(OFFENSE_COLUMNS, totals, strict=True)
    )
    body = ""
    for row in rows:
        values = (row.count, row.closed_by_soc, row.reported, row.no_action)
        body += (
            f"<tr><td style='{TD}'>{_cell(row.rule)}</td>"
            + "".join(
                f"<td style='{TD} text-align:center; font-size:1.4em; background-color:{cell};'>{value}</td>"
                for (_, _, cell), value in zip(OFFENSE_COLUMNS, values, strict=True)
            )
            + "</tr>"
        )
    if not rows:
        body = f"<tr><td style='{TD}' colspan='5'>No offenses in this period</td></tr>"
    intro = (
        f"<p style='{FONT}'>Hello,</p>"
        f"<p style='{FONT}'>The table below summarises the actions taken on offenses received in the last {hours} hours.</p>"
    )
    content = (
        f"<table style='{TABLE} table-layout:fixed;'>"
        f"<tr><td colspan='5' style='{title_cell}'>Last {hours} Hours of Offense Action Information</td></tr>"
        f"<tr>{header}</tr>{body}</table>"
    )
    return _document(f"Last {hours} hours offense summary", intro + content)


def render_failure(job: str, error: BaseException, context: str | None = None) -> str:
    """Mail body sent to the operators when a scheduled job fails."""
    details = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    body = (
        f"<h2 style='{FONT} color:#c00000;'>{escape(job)} failed</h2>"
        f"<p style='{FONT}'><b>Time:</b> {datetime.now():%Y-%m-%d %H:%M:%S}</p>"
        f"<p style='{FONT}'><b>Error:</b> {escape(repr(error))}</p>"
        f"<h3 style='{FONT}'>Traceback</h3><pre style='white-space:pre-wrap;'>{escape(details)}</pre>"
    )
    if context:
        body += f"<h3 style='{FONT}'>Context</h3><pre style='white-space:pre-wrap;'>{escape(context[:4000])}</pre>"
    return _document(f"{job} failed", body)
