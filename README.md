# SOAR Periodic Reports

[![CI](https://github.com/AtakanUk/soar-periodic-reports/actions/workflows/ci.yml/badge.svg)](https://github.com/AtakanUk/soar-periodic-reports/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Scheduled SOC reports built on the IBM QRadar SOAR and QRadar SIEM REST APIs. Each report is a sub-command meant to be run from cron (or any scheduler) and delivered by mail.

| Command | Schedule | What it produces |
| --- | --- | --- |
| `weekly` | weekly | SOC operations summary: resolution metrics, automation metrics, top and newly seen incident types, false positives and high-severity incidents |
| `daily-offenses` | daily | Per-rule table of the offenses received in the last 24 hours and what happened to them (closed by SOC, reported to the customer, still waiting) |
| `logsource-health` | daily | Finds QRadar log sources in `ERROR` state that have been silent for 48 hours and opens a control incident in SOAR listing them |
| `sla` | weekly | Analyst SLA workbook (Excel): time from incident creation to customer notification, per analyst and per incident |

## Highlights

- **No hard-coded IDs.** Resolution and severity values are resolved to labels through `/types/incident/fields/<field>`, so the same configuration works on any SOAR instance; metrics are configured by label (`False-Positive`, `Action Taken`, …).
- **HA-aware log source check.** When only one member of a cluster pair is in error the other one is still receiving traffic, so that member is not reported. Pairs, excluded names and excluded log source groups are configurable.
- **Office 365 ready mail delivery.** SMTP with no auth, basic login, or OAuth2 (`XOAUTH2` using a refresh token), which Exchange Online requires once basic SMTP AUTH is disabled.
- **Failure notifications.** With `--notify-errors`, a crash in any job mails the traceback to `ALERT_MAIL_TO` instead of failing silently in cron.

## How the reports are calculated

**weekly** queries three incident sets: incidents reported to the customer in the last `WEEKLY_DAYS` (where `properties.date_reported` has a value), the same for the preceding `WEEKLY_BASELINE_DAYS` and every incident created in the period.

- *Offense Count / Incident Count* compares everything that was raised (minus automation and control incidents) with what was escalated to the customer.
- Resolution metrics count reported incidents per resolution label; *No Response* counts the ones without a resolution.
- The incident type is taken from names of the form `Prefix: Rule name - <id>`. Types that appear this week but not in the baseline window are listed as new.
- The automation table counts incidents by name pattern and collects blocked IPs and domains from comma-separated custom fields.

**daily-offenses** groups the last `DAILY_HOURS` of incidents by the rule name found after `categories:` in the incident description, then counts closed-by-SOC (closed without reporting), reported and no-action (active, not reported) incidents per rule.

**logsource-health** reads `/api/config/event_sources/log_source_management/log_sources` filtered to `status="ERROR"`, keeps sources with no events for `LOGSOURCE_STALE_HOURS`, applies the exclusions and HA logic, and creates an incident whose custom field holds `name_type_lastEventTime` entries. A control incident is created on every run (with an empty list when everything is healthy), so a playbook can close clean runs and alert on the others.

**sla** measures `reported_date - create_date` for each incident of the last `SLA_DAYS` (unreported incidents are measured up to now), flags the ones above `SLA_THRESHOLD_MINUTES` and writes a two-sheet workbook with an average per analyst and clickable incident links.

## Project layout

```text
src/soar_periodic_reports/
├── cli.py             # sub-commands and orchestration
├── config.py          # environment-based settings
├── soar_client.py     # SOAR queries (date range paging, field labels, incident creation)
├── qradar_client.py   # QRadar log source API
├── analytics.py       # all report calculations (pure functions)
├── renderers.py       # HTML mail bodies
├── excel_writer.py    # SLA workbook
└── emailer.py         # SMTP / XOAUTH2 delivery
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
cp .env.example .env             # then fill in the values
```

Requires Python 3.11+, a SOAR API key that can read incidents and incident type definitions (and create incidents for `logsource-health`), and a QRadar authorized service token for `logsource-health`.

## Configuration

Settings come from environment variables or a `.env` file. `.env.example` lists every variable with a short comment; the most important ones:

| Variable | Description |
| --- | --- |
| `SOAR_HOST`, `SOAR_PORT`, `SOAR_ORG`, `SOAR_API_KEY_ID`, `SOAR_API_KEY_SECRET`, `SOAR_CAFILE` | SOAR connection |
| `QRADAR_HOST`, `QRADAR_API_TOKEN`, `QRADAR_API_VERSION`, `QRADAR_VERIFY_SSL` / `QRADAR_CA_BUNDLE` | QRadar connection |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_AUTH` (`none`/`login`/`oauth2`), `SMTP_STARTTLS` | Mail transport |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | Basic login, also the mailbox for OAuth2 |
| `SMTP_OAUTH_TENANT_ID`, `SMTP_OAUTH_CLIENT_ID`, `SMTP_OAUTH_CLIENT_SECRET`, `SMTP_OAUTH_REFRESH_TOKEN` | OAuth2 refresh-token flow |
| `MAIL_FROM`, `MAIL_TO`, `MAIL_CC` | Default sender and recipients |
| `WEEKLY_MAIL_TO`, `DAILY_MAIL_TO`, `SLA_MAIL_TO`, `ALERT_MAIL_TO` (+ `_CC`) | Per-report recipients, falling back to `MAIL_TO` |
| `WEEKLY_RESOLUTION_METRICS`, `WEEKLY_FALSE_POSITIVE_LABEL`, `WEEKLY_SEVERITIES` | Labels used by the weekly report |
| `WEEKLY_OFFENSE_COUNT_EXCLUDE`, `WEEKLY_NAME_COUNTERS` | Name patterns for automation/control incidents |
| `WEEKLY_HONEYPOT_IP_FIELD`, `WEEKLY_FIREWALL_IP_FIELD`, `WEEKLY_FIREWALL_FLAG_FIELD`, `WEEKLY_PROXY_DOMAIN_FIELD` | Custom fields for the automation table (empty = row skipped) |
| `DAILY_HOURS`, `DAILY_EXCLUDE_PATTERNS`, `DAILY_FALLBACK_RULE` | 24 hour summary |
| `LOGSOURCE_STALE_HOURS`, `LOGSOURCE_EXCLUDE_NAMES`, `LOGSOURCE_HA_PAIRS`, `LOGSOURCE_EXCLUDE_GROUP_IDS` | Log source check |
| `LOGSOURCE_INCIDENT_NAME`, `LOGSOURCE_INCIDENT_FIELD` | Control incident name and the custom text field it fills |
| `SLA_DAYS`, `SLA_THRESHOLD_MINUTES`, `SLA_ANALYST_FIELD`, `SLA_REPORTED_FIELD` | SLA report |

Field names such as `customer_response`, `analyst` or `reported_date` are custom incident fields; set them to the API names used in your organization.

## Usage

```bash
soar-reports weekly --send-mail
soar-reports daily-offenses --send-mail
soar-reports logsource-health --dry-run        # print findings only
soar-reports --notify-errors logsource-health  # create the control incident, mail on failure
soar-reports sla --output-dir /var/reports --send-mail
```

Reports are also written to `--output-dir` (default `reports/`). Example crontab:

```cron
0 8 * * 1   cd /opt/soar-reports && .venv/bin/soar-reports --notify-errors weekly --send-mail
0 9 * * *   cd /opt/soar-reports && .venv/bin/soar-reports --notify-errors daily-offenses --send-mail
0 */6 * * * cd /opt/soar-reports && .venv/bin/soar-reports --notify-errors logsource-health
30 8 * * 1  cd /opt/soar-reports && .venv/bin/soar-reports --notify-errors sla --send-mail
```

## Tests

```bash
pip install pytest
pytest
```

The tests run offline against fake API clients and cover every calculation, the HTML/Excel output and the mail helpers.

## License

[MIT](LICENSE)
