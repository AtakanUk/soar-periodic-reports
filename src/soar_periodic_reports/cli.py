"""Command-line entry point: one sub-command per scheduled report."""

from __future__ import annotations

import argparse
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import analytics
from .config import (
    ConfigError,
    MailSettings,
    QRadarSettings,
    SoarSettings,
    env,
    env_int,
    env_labelled,
    env_list,
    env_pairs,
)

log = logging.getLogger("soar_periodic_reports")

REPORTED = [{"field_name": "properties.date_reported", "method": "has_a_value"}]


def _ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def _connect_soar():
    from .soar_client import SoarClient

    settings = SoarSettings.from_env()
    return settings, SoarClient.connect(settings)


def _write(output_dir: Path, name: str, content: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / name
    path.write_text(content, encoding="utf-8")
    log.info("Wrote %s", path)
    return path


def _mail(
    prefix: str, subject: str, html_body: str | None = None, text: str | None = None, attachments=()
) -> None:
    from .emailer import build_message, send

    settings = MailSettings.from_env(prefix)
    send(
        settings,
        build_message(
            settings, subject, html_body=html_body, text_body=text, attachments=attachments
        ),
    )


def run_weekly(args: argparse.Namespace) -> None:
    from .renderers import render_weekly

    days = env_int("WEEKLY_DAYS", 7)
    baseline_days = env_int("WEEKLY_BASELINE_DAYS", 60)
    options = analytics.WeeklyOptions(
        resolution_metrics=env_list(
            "WEEKLY_RESOLUTION_METRICS", "False-Positive,Action Taken,Known Activity,Non-Issue"
        ),
        false_positive_label=env("WEEKLY_FALSE_POSITIVE_LABEL", "False-Positive"),
        highlighted_severities=env_list("WEEKLY_SEVERITIES", "Critical"),
        offense_count_exclude=env_list("WEEKLY_OFFENSE_COUNT_EXCLUDE"),
        name_counters=env_labelled("WEEKLY_NAME_COUNTERS"),
        customer_response_field=env("WEEKLY_CUSTOMER_RESPONSE_FIELD", "customer_response"),
        honeypot_ip_field=env("WEEKLY_HONEYPOT_IP_FIELD"),
        firewall_ip_field=env("WEEKLY_FIREWALL_IP_FIELD"),
        firewall_flag_field=env("WEEKLY_FIREWALL_FLAG_FIELD"),
        proxy_domain_field=env("WEEKLY_PROXY_DOMAIN_FIELD"),
    )

    _, soar = _connect_soar()
    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    baseline_start = start - timedelta(days=baseline_days)

    report = analytics.build_weekly_report(
        reported=soar.incidents_created_between(_ms(start), _ms(end), REPORTED),
        reported_baseline=soar.incidents_created_between(_ms(baseline_start), _ms(start), REPORTED),
        all_incidents=soar.incidents_created_between(_ms(start), _ms(end)),
        resolution_labels=soar.field_labels("resolution_id"),
        severity_labels=soar.field_labels("severity_code"),
        options=options,
        period_start=start,
        period_end=end,
    )
    html = render_weekly(report)
    _write(Path(args.output_dir), f"weekly_soc_report_{end:%Y-%m-%d}.html", html)
    if args.send_mail:
        subject = f"{env('WEEKLY_MAIL_SUBJECT', 'Weekly SOC Report')} [{end:%d-%m-%Y}]"
        _mail("WEEKLY_", subject, html_body=html)


def run_daily(args: argparse.Namespace) -> None:
    from .renderers import render_offense_summary

    hours = env_int("DAILY_HOURS", 24)
    _, soar = _connect_soar()
    end = datetime.now(UTC)
    incidents = soar.incidents_created_between(_ms(end - timedelta(hours=hours)), _ms(end))
    rows = analytics.build_offense_summary(
        incidents,
        exclude=env_list("DAILY_EXCLUDE_PATTERNS"),
        fallback_rule=env("DAILY_FALLBACK_RULE", "Uncategorized"),
    )
    html = render_offense_summary(rows, hours)
    _write(Path(args.output_dir), f"offense_summary_{end:%Y-%m-%d_%H%M}.html", html)
    if args.send_mail:
        _mail(
            "DAILY_",
            env("DAILY_MAIL_SUBJECT", f"Offense summary for the last {hours} hours"),
            html_body=html,
        )


def run_logsource_health(args: argparse.Namespace) -> None:
    from .qradar_client import QRadarClient

    qradar = QRadarClient(QRadarSettings.from_env())
    now = datetime.now(UTC)
    failing = analytics.failing_log_sources(
        qradar.log_sources_in_error(),
        now=now,
        stale_hours=env_int("LOGSOURCE_STALE_HOURS", 48),
        exclude_names=env_list("LOGSOURCE_EXCLUDE_NAMES"),
        ha_pairs=env_pairs("LOGSOURCE_HA_PAIRS"),
        excluded_group_ids=[int(g) for g in env_list("LOGSOURCE_EXCLUDE_GROUP_IDS")],
    )
    summary = analytics.describe_log_sources(failing, qradar.log_source_type_names())
    log.info("%d log source(s) in ERROR state without events", len(failing))

    incident = analytics.log_source_incident(
        description="Control incident listing QRadar log sources in ERROR state",
        field_name=env("LOGSOURCE_INCIDENT_FIELD", "qradar_error_log_sources"),
        value=summary,
        now=now,
        name=env("LOGSOURCE_INCIDENT_NAME", "QRadar Log Source ERROR Check"),
    )
    if args.dry_run:
        for item in summary.split(",") if summary else []:
            print(item)
        return
    _, soar = _connect_soar()
    created = soar.create_incident(incident)
    log.info("Created control incident %s", created.get("id"))


def run_sla(args: argparse.Namespace) -> None:
    from .excel_writer import write_sla_workbook

    days = env_int("SLA_DAYS", 7)
    threshold = env_int("SLA_THRESHOLD_MINUTES", 120)
    settings, soar = _connect_soar()
    end = datetime.now(UTC)
    incidents = soar.incidents_created_between(_ms(end - timedelta(days=days)), _ms(end))

    summaries, details = analytics.build_sla_report(
        incidents,
        analyst_field=env("SLA_ANALYST_FIELD", "analyst"),
        reported_field=env("SLA_REPORTED_FIELD", "reported_date"),
        threshold=timedelta(minutes=threshold),
        now=end,
        incident_url=lambda i: (
            f"{settings.ui_base_url}/#incidents/{i.get('id')}?orgId={i.get('org_id')}"
        ),
    )
    path = write_sla_workbook(
        Path(args.output_dir) / f"sla_report_{end:%Y-%m-%d}.xlsx", summaries, details, threshold
    )
    log.info("Wrote %s (%d incidents, %d analysts)", path, len(details), len(summaries))
    if args.send_mail:
        text = f"Attached is the analyst SLA report for the last {days} days (threshold: {threshold} minutes)."
        _mail("SLA_", env("SLA_MAIL_SUBJECT", "Analyst SLA Report"), text=text, attachments=[path])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soar-reports", description="Scheduled SOC reports for IBM QRadar SOAR"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")
    parser.add_argument(
        "--notify-errors",
        action="store_true",
        help="mail a failure report to ALERT_MAIL_TO if the job crashes",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    def add(name: str, handler, help_text: str, mail: bool = True):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument(
            "--output-dir", default="reports", help="output directory (default: reports)"
        )
        if mail:
            sub.add_argument(
                "--send-mail",
                action="store_true",
                help="mail the report to the configured recipients",
            )
        sub.set_defaults(handler=handler)
        return sub

    add("weekly", run_weekly, "weekly SOC metrics report")
    add("daily-offenses", run_daily, "offense action summary for the last DAILY_HOURS hours")
    health = add(
        "logsource-health", run_logsource_health, "QRadar log source error check", mail=False
    )
    health.add_argument(
        "--dry-run", action="store_true", help="print the findings instead of creating an incident"
    )
    add("sla", run_sla, "analyst SLA report as an Excel workbook")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    try:
        args.handler(args)
        return 0
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        return 2
    except Exception as exc:
        log.exception("%s failed", args.command)
        if args.notify_errors:
            _notify_failure(args.command, exc)
        return 1


def _notify_failure(job: str, error: Exception) -> None:
    from .renderers import render_failure

    try:
        _mail("ALERT_", f"[SOAR reports] {job} failed", html_body=render_failure(job, error))
    except Exception:
        log.exception("Could not send the failure notification")


if __name__ == "__main__":
    raise SystemExit(main())
