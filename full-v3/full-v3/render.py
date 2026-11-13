"""Render the same host snapshots to the controller's HTML and CSV reports."""

import csv
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from string import Template
from uuid import uuid4

CVE_DETAILS = "CVEs in pending security advisories"
SEVERITIES = ("critical", "important", "moderate", "low")
COLUMNS = ("host", "address", "status", "os", "kernel", "collected", "booted",
           "uptime_seconds", "critical", "important", "moderate", "low",
           "other_advisories", "reboot_required", "listeners", "unexpected_listeners",
           "running_services", "failed_units", "selinux", "errors", "advisory_ids",
           "listener_details", "unexpected_listener_details", "service_details", "failed_unit_details",
           "platform", "ssh_policy", "uid_zero_accounts", "admin_group_members", "sudoers_paths")


def report_access(row, details, data):
    ssh = data.get("ssh_policy", {})
    policy = ssh.get("values")
    if policy:
        details["Effective SSH policy"] = [ssh["context"]] + [
            "{}: {}".format(user, ", ".join("{}={}".format(key, value)
                                           for key, value in sorted(settings.items())))
            for user, settings in sorted(policy.items())
        ]
        root_login = policy.get("root", {}).get("permitrootlogin")
        ssh_risk = (root_login not in (None, "Unknown", "no")
                    or any(settings.get(key) == "yes" for settings in policy.values()
                           for key in ("passwordauthentication", "permitemptypasswords")))
        if ssh_risk:
            row["ssh_policy"] = "Review"
        elif all("Unknown" not in settings.values() for settings in policy.values()):
            row["ssh_policy"] = "Restricted"
    else:
        details["Effective SSH policy"] = [ssh.get("error", "Unknown")]

    access = data.get("privileged_access", {})
    if "uid_zero" in access:
        row["uid_zero_accounts"] = ", ".join(access["uid_zero"])
    if "admin_groups" in access:
        row["admin_group_members"] = " | ".join(
            "{}: {}".format(group, ", ".join(members) or "No members")
            for group, members in sorted(access["admin_groups"].items()))
    if "sudoers" in access:
        row["sudoers_paths"] = " | ".join(sorted(access["sudoers"]))
    details["Local privileged access"] = [
        "UID 0 accounts: {}".format(row["uid_zero_accounts"]),
        "Admin groups: {}".format(row["admin_group_members"] or "None found"),
        "Sudoers paths: {}".format(row["sudoers_paths"] or "None found"),
    ]
    if "error" in access:
        details["Local privileged access"].append(access["error"])
    return row["ssh_policy"] == "Review" or any(user != "root" for user in access.get("uid_zero", ()))


def assess(entry):
    row = {key: "unknown" for key in COLUMNS}
    row.update(host=entry["host"], address=entry["address"], platform="Unknown", ssh_policy="Unknown")
    errors = []
    details = {}
    try:
        if entry["unreachable"] or entry["failed"]:
            raise ValueError(entry["message"] or "Collection failed")
        data = json.loads(entry["stdout"])
    except ValueError as exc:
        row.update(status="Unreachable" if entry["unreachable"] else "Unknown",
                   errors=str(exc))
        return row, details

    for field in ("os", "kernel", "collected", "booted", "uptime_seconds"):
        row[field] = data[field]
    row["platform"] = data.get("platform") or "Unknown"

    for key in ("advisories", "reboot", "listeners", "services", "failed_units", "selinux", "firewall"):
        if "error" in data[key]:
            errors.append("{}: {}".format(key, data[key]["error"]))

    advisories = data["advisories"].get("values")
    if advisories is not None:
        for severity in SEVERITIES:
            row[severity] = sum(value == severity for value in advisories.values())
        row["other_advisories"] = sum(value not in SEVERITIES for value in advisories.values())
        details["Pending security advisories"] = ["{} {}".format(key, value)
                                                 for key, value in sorted(advisories.items())]
        row["advisory_ids"] = " | ".join(details["Pending security advisories"])
    cves = data.get("cves", {})
    if "values" in cves:
        details[CVE_DETAILS] = cves["values"]
    if "error" in cves:
        errors.append("CVEs: " + cves["error"])
    if "value" in data["reboot"]:
        row["reboot_required"] = "yes" if data["reboot"]["value"] else "no"
    if "output" in data["selinux"]:
        row["selinux"] = data["selinux"]["output"]
    for key, field, label in (("listeners", "listeners", "Local listening sockets"),
                               ("services", "running_services", "Running services"),
                               ("failed_units", "failed_units", "Failed units"),
                               ("firewall", None, "Host firewall configuration")):
        if "values" in data[key]:
            details[label] = data[key]["values"]
            if field:
                row[field] = len(details[label])
    for column, title in (("listener_details", "Local listening sockets"),
                          ("service_details", "Running services"),
                          ("failed_unit_details", "Failed units")):
        if title in details:
            row[column] = " | ".join(details[title])
    if "values" in data["listeners"]:
        unexpected = []
        allowed = set(entry["allowed"])
        for line in data["listeners"]["values"]:
            fields = line.split()
            if len(fields) < 5:
                errors.append("Unrecognised socket row: " + line)
                continue
            address, _, port = fields[4].rpartition(":")
            if address.strip("[]").split("%", 1)[0] in ("::1",) or address.startswith("127."):
                continue
            if "{}:{}".format(fields[0], port) not in allowed:
                unexpected.append(line)
        row["unexpected_listeners"] = len(unexpected)
        details["Unexpected non-loopback listeners"] = unexpected
        row["unexpected_listener_details"] = " | ".join(unexpected)

    access_risk = report_access(row, details, data)
    if any(isinstance(row[key], int) and row[key] > 0
                                    for key in ("critical", "important")):
        row["status"] = "Urgent"
    elif (access_risk or any(isinstance(row[key], int) and row[key] > 0 for key in
              ("moderate", "low", "other_advisories", "unexpected_listeners", "failed_units"))
          or row["reboot_required"] == "yes" or row["selinux"] in ("Permissive", "Disabled")
          or data["firewall"].get("values") == ["No active nftables rules"]):
        row["status"] = "Review"
    else:
        incomplete = any(row[key].lower() == "unknown" for key in (
            "ssh_policy", "uid_zero_accounts", "admin_group_members", "sudoers_paths"))
        row["status"] = "Unknown" if errors or incomplete else "OK"
    row["errors"] = " | ".join(errors)
    return row, details


def write_atomic(path, content):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                     dir=path.parent, delete=False) as temporary:
        temporary.write(content)
        os.fchmod(temporary.fileno(), 0o644)
    os.replace(temporary.name, path)


def csv_value(value):
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def html_report(results, table_rows, snapshot_id):
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = [row for row, _ in results]
    metrics = {
        "Inventory hosts": len(rows),
        "Urgent": sum(row["status"] == "Urgent" for row in rows),
        "Review": sum(row["status"] == "Review" for row in rows),
        "OK": sum(row["status"] == "OK" for row in rows),
        "Unreachable": sum(row["status"] == "Unreachable" for row in rows),
        "Unknown": sum(row["status"] == "Unknown" for row in rows),
        "Collection errors": sum(bool(row["errors"]) for row in rows),
        "Reboot required": sum(row["reboot_required"] == "yes" for row in rows),
        "Unexpected listeners": sum(isinstance(row["unexpected_listeners"], int)
                                   and row["unexpected_listeners"] > 0 for row in rows),
    }
    colors = {"Urgent": "urgent", "Review": "review", "OK": "ok",
              "Unknown": "unknown", "Unreachable": "unreachable"}
    cards = "".join('<div class="card {}"><strong>{}</strong>{}</div>'.format(
                    colors.get(label, "") if count else "", count, label)
                    for label, count in metrics.items())
    table_json = json.dumps(table_rows, separators=(",", ":")).replace("<", "\\u003c")
    template = Template(Path(__file__).with_name("report.html").read_text(encoding="utf-8"))
    return template.substitute(generated=generated, cards=cards, table_json=table_json,
                               snapshot_id=snapshot_id)


def display_row(row):
    display = dict(row)
    for field in ("collected", "booted"):
        if row[field] != "unknown":
            display[field] = datetime.fromisoformat(row[field]).strftime("%Y/%m/%d")
    seconds = row["uptime_seconds"]
    display["uptime_days"] = "{:.2f}".format(seconds / 86400) if isinstance(seconds, int) else "unknown"
    return display


def host_details(row, details):
    fields = ("address", "os", "platform", "kernel", "collected", "booted", "uptime_days",
              *SEVERITIES, "other_advisories", "reboot_required", "listeners",
              "unexpected_listeners", "running_services", "failed_units", "selinux", "ssh_policy")
    facts = "".join("<div><dt>{}</dt><dd>{}</dd></div>".format(
                    key.replace("_", " ").capitalize(), escape(str(row[key]))) for key in fields)
    blocks = "".join("<details><summary>{} ({})</summary><pre>{}</pre></details>".format(
                     escape(label), len(values), escape("\n".join(values) or "None observed"))
                     for label, values in details.items())
    errors = '<p class="error">{}</p>'.format(escape(row["errors"])) if row["errors"] else ""
    return "<dl>{}</dl>{}{}".format(facts, errors, blocks)


def prometheus_metrics(results, generated):
    rows = [row for row, _ in results]
    lines = []

    def gauge(name, samples):
        metric = "fleet_security_" + name
        lines.append("# TYPE {} gauge".format(metric))
        for labels, value in samples:
            pairs = []
            for key, label in labels.items():
                escaped = label.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
                pairs.append('{}="{}"'.format(key, escaped))
            suffix = "{" + ",".join(pairs) + "}" if pairs else ""
            lines.append("{}{} {}".format(metric, suffix, value))

    gauge("report_generated_timestamp_seconds", [({}, int(generated.timestamp()))])
    statuses = ("OK", "Review", "Urgent", "Unknown", "Unreachable")
    gauge("hosts", [({"status": status.lower()}, sum(row["status"] == status for row in rows))
                    for status in statuses])
    gauge("host_status", [({"host": row["host"]}, statuses.index(row["status"])) for row in rows])
    gauge("host_collected_timestamp_seconds", [
        ({"host": row["host"]}, int(datetime.fromisoformat(row["collected"]).timestamp()))
        for row in rows if row["collected"] != "unknown"])
    gauge("pending_advisories", [
        ({"host": row["host"], "severity": severity}, row[field])
        for row in rows for severity, field in
        [(name, name) for name in SEVERITIES] + [("other", "other_advisories")]
        if isinstance(row[field], int)])
    for field in ("unexpected_listeners", "failed_units"):
        gauge(field, [({"host": row["host"]}, row[field]) for row in rows
                      if isinstance(row[field], int)])
    gauge("reboot_required", [({"host": row["host"]}, int(row["reboot_required"] == "yes"))
                              for row in rows if row["reboot_required"] in ("yes", "no")])
    return "\n".join(lines) + "\n"


source, destination = map(Path, sys.argv[1:])
results = [assess(entry) for entry in json.loads(source.read_text())]
status_order = {status: index for index, status in
                enumerate(("Urgent", "Unreachable", "Unknown", "Review", "OK"))}
results.sort(key=lambda item: (status_order[item[0]["status"]], item[0]["host"]))
output = io.StringIO(newline="")
csv_columns = tuple("uptime_days" if field == "uptime_seconds" else field for field in COLUMNS)
writer = csv.DictWriter(output, fieldnames=csv_columns)
writer.writeheader()
for row, _ in results:
    display = display_row(row)
    writer.writerow({key: csv_value(display[key]) for key in csv_columns})
snapshots = destination / "snapshots"
snapshots.mkdir(exist_ok=True)
snapshot_id = uuid4().hex
table_fields = ("host", "address", "status", "os", "platform", "critical", "important",
                "unexpected_listeners", "reboot_required")
table_rows = []
cve_index = {}
with tempfile.TemporaryDirectory(prefix=".pending-", dir=snapshots) as temporary:
    staging = Path(temporary)
    (staging / "hosts").mkdir()
    (staging / "cves").mkdir()
    for row, details in results:
        fragment = host_details(display_row(row), details)
        digest = hashlib.sha256(row["host"].encode("utf-8")).hexdigest()
        write_atomic(staging / "hosts" / (digest + ".html"), fragment)
        for cve in details.get(CVE_DETAILS, ()):
            if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
                cve_index.setdefault(cve, []).append(len(table_rows))
        table_rows.append([row[field] for field in table_fields] + [digest])
    for cve, hosts in cve_index.items():
        write_atomic(staging / "cves" / (cve + ".json"), json.dumps(hosts, separators=(",", ":")))
    write_atomic(staging / "cves" / "ready.json", "{}")
    staging.chmod(0o755)
    staging.rename(snapshots / snapshot_id)
write_atomic(destination / "security-report.csv", output.getvalue())
write_atomic(destination / "index.html", html_report(results, table_rows, snapshot_id))
write_atomic(destination / "metrics", prometheus_metrics(results, datetime.now(timezone.utc)))
# Retain the prior generation for tabs that were open during the refresh.
older = [path for path in snapshots.iterdir()
         if path.is_dir() and path.name != snapshot_id and re.fullmatch(r"[a-f0-9]{32}", path.name)]
for path in sorted(older, key=lambda path: path.stat().st_mtime, reverse=True)[1:]:
    shutil.rmtree(path)
