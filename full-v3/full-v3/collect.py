"""Run local checks on an RHEL host and emit one JSON record."""

import hashlib
import io
import json
import os
import platform
import re
import shlex
import subprocess
import sys
from datetime import datetime


def run(args, timeout=15, valid=(0,)):
    try:
        process = subprocess.Popen(
            ["timeout", "-k", "5s", str(timeout)] + args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL="C"))
        stdout, stderr = (stream.decode("utf-8", "replace").strip()
                          for stream in process.communicate())
    except OSError as exc:
        return {"error": str(exc)}
    if process.returncode in (124, 137):
        return {"error": "{} timed out after {} seconds".format(args[0], timeout)}
    if process.returncode not in valid:
        return {"error": stderr or stdout or "Exit status {}".format(process.returncode)}
    return {"output": stdout, "code": process.returncode}


def read(path):
    with io.open(path, encoding="utf-8") as source:
        return source.read()


def available(command):
    return any(os.access(os.path.join(directory, command), os.X_OK)
               for directory in os.environ.get("PATH", "").split(os.pathsep))


def lines(result):
    if "output" in result:
        return {"values": result["output"].splitlines()}
    return result


def ssh_policy(connection, user, client_hostname):
    fields = connection.split()
    if len(fields) != 4 or not re.match(r"^[A-Za-z0-9_.-]+$", user):
        return {"error": "Management SSH connection context unavailable"}
    source, _, local, port = fields
    host = client_hostname or source
    if not (re.match(r"^[0-9A-Fa-f:.%]+$", source)
            and re.match(r"^[0-9A-Fa-f:.%]+$", local) and port.isdigit()
            and re.match(r"^[A-Za-z0-9_.:%-]+$", host)):
        return {"error": "Management SSH connection context is invalid"}
    values = {}
    for account in sorted({user, "root"}):
        context = "user={},host={},addr={},laddr={},lport={}".format(
            account, host, source, local, port)
        result = run(["/usr/sbin/sshd", "-T", "-C", context], 5)
        if "error" in result:
            return {"error": "Cannot evaluate SSH policy for {}: {}".format(account, result["error"])}
        config = dict(line.split(None, 1) for line in result["output"].splitlines()
                      if len(line.split(None, 1)) == 2)
        keys = ("permitrootlogin", "passwordauthentication", "permitemptypasswords")
        values[account] = {key: config.get(key, "Unknown") for key in keys}
    return {"values": values, "context": "{} to {} port {} (client host {})".format(
        source, local, port, host)}


def privileged_access():
    result = {}
    try:
        accounts = [line.split(":") for line in read("/etc/passwd").splitlines()]
        result["uid_zero"] = sorted(account[0] for account in accounts
                                    if len(account) > 2 and account[2] == "0")
        result["admin_groups"] = {}
        for line in read("/etc/group").splitlines():
            fields = line.split(":")
            if len(fields) == 4 and fields[0] in ("wheel", "sudo"):
                members = set(filter(None, fields[3].split(",")))
                for account in accounts:
                    if len(account) > 3 and account[3] == fields[2]:
                        members.add(account[0])
                result["admin_groups"][fields[0]] = sorted(members)
        paths = ["/etc/sudoers"]
        if os.path.isdir("/etc/sudoers.d"):
            paths.extend(os.path.join("/etc/sudoers.d", name)
                         for name in sorted(os.listdir("/etc/sudoers.d"))
                         if "." not in name and not name.endswith("~"))
        hashes = {}
        for path in paths:
            if os.path.isfile(path):
                with open(path, "rb") as policy:
                    hashes[path] = hashlib.sha256(policy.read()).hexdigest()
        result["sudoers"] = hashes
    except (IOError, OSError) as exc:
        result["error"] = str(exc)
    return result


release = {}
for line in read("/etc/os-release").splitlines():
    key, separator, value = line.partition("=")
    if separator and not key.startswith("#"):
        release[key] = " ".join(shlex.split(value))

dnf = ["dnf", "-q", "--setopt=skip_if_unavailable=False", "--setopt=timeout=20",
       "--setopt=retries=2"]
repository_options = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
if repository_options.get("proxy"):
    dnf.append("--setopt=proxy=" + repository_options["proxy"])
for repo, url in sorted(repository_options.get("repositories", {}).items()):
    dnf.extend(["--repofrompath={},{}".format(repo, url), "--repo=" + repo])

subscription_message = "Updating Subscription Management repositories."
if not available("dnf"):
    advisory_result = {"error": "DNF is unavailable"}
else:
    repositories = run(dnf + ["repolist", "--enabled"], 30)
    if "error" in repositories:
        advisory_result = repositories
    elif not re.search(r"^repo id[ \t]+repo name[^\n]*\n[ \t]*\S+[ \t]+\S",
                       repositories["output"], re.MULTILINE):
        advisory_result = {"error": "No enabled DNF repositories were listed"}
    else:
        advisory_result = run(dnf + ["--refresh", "updateinfo", "list", "updates", "security"], 180)
advisories = advisory_result
if "output" in advisory_result:
    records = {}
    unexpected = []
    for line in advisory_result["output"].splitlines():
        match = re.match(r"^\s*(\S+)\s+(\S+)/Sec\.?(?:\s|$)", line, re.IGNORECASE)
        if match:
            records[match[1]] = match[2].lower()
        elif line.strip() and not line.lstrip().startswith(("Last metadata expiration check:", subscription_message)):
            unexpected.append(line)
    advisories = {"values": records}
    if unexpected:
        advisories = {"error": "Unrecognised advisory output: " + unexpected[0]}

cves = {}
if "values" in advisories:
    cves = run(dnf + ["--cacheonly", "updateinfo", "list", "updates", "security", "--with-cve"], 60)
    if "output" in cves:
        ids = set()
        for line in cves["output"].splitlines():
            match = re.match(r"^\s*(CVE-\d{4}-\d{4,})\s", line, re.IGNORECASE)
            if match:
                ids.add(match[1].upper())
        cves = {"values": sorted(ids)}


boot_time = next(int(line.split()[1]) for line in read("/proc/stat").splitlines()
                 if line.startswith("btime "))
if available("dnf"):
    reboot_command = ["dnf", "-q", "--disablerepo=*", "needs-restarting", "-r"]
else:
    reboot_command = ["needs-restarting", "-r"]
reboot = run(reboot_command, 20, (0, 1))
if "code" in reboot:
    if reboot["code"] == 0 or "Reboot is required" in reboot["output"]:
        reboot = {"value": reboot["code"] == 1}
    else:
        reboot = {"error": reboot["output"] or "Reboot check returned an ambiguous exit status"}

firewall_state = run(["firewall-cmd", "--state"], valid=(0, 252))
firewall = firewall_state
if firewall_state.get("output") == "running":
    firewall = lines(run(["firewall-cmd", "--list-all-zones"]))
elif firewall_state.get("output") == "not running" or not available("firewall-cmd"):
    if available("nft"):
        firewall = lines(run(["nft", "list", "ruleset"]))
    elif available("iptables-save") and available("ip6tables-save"):
        ipv4 = lines(run(["iptables-save"]))
        ipv6 = lines(run(["ip6tables-save"]))
        if "error" in ipv4 or "error" in ipv6:
            firewall = {"error": ipv4.get("error") or ipv6.get("error")}
        else:
            firewall = {"values": ["IPv4"] + ipv4["values"] + ["IPv6"] + ipv6["values"]}
    else:
        firewall = {"error": "Firewalld is unavailable or inactive, and no ruleset tool is available"}
    if "values" in firewall:
        if firewall["values"]:
            firewall["values"].insert(0, "Active nftables rules")
        else:
            firewall["values"] = ["No active nftables rules"]

listeners = lines(run(["ss", "-lntup"]))
if listeners.get("values") and listeners["values"][0].startswith("Netid"):
    listeners["values"].pop(0)

virtualization = run(["systemd-detect-virt"], 5, (0, 1))
host_platform = "Unknown"
if virtualization.get("code") == 1 and virtualization.get("output") == "none":
    host_platform = "Physical"
elif virtualization.get("code") == 0 and virtualization.get("output"):
    name = virtualization["output"]
    host_platform = {"kvm": "KVM", "vmware": "VMware", "qemu": "QEMU"}.get(name, name)

print(json.dumps({
    "collected": datetime.utcnow().isoformat() + "+00:00",
    "os": release.get("PRETTY_NAME", "Unknown"),
    "kernel": platform.release(),
    "platform": host_platform,
    "booted": datetime.utcfromtimestamp(boot_time).isoformat() + "+00:00",
    "uptime_seconds": int(float(read("/proc/uptime").split()[0])),
    "advisories": advisories,
    "cves": cves,
    "reboot": reboot,
    "listeners": listeners,
    "services": lines(run(["systemctl", "list-units", "--type=service", "--state=running",
                           "--no-legend", "--no-pager", "--plain"])),
    "failed_units": lines(run(["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"])),
    "selinux": run(["getenforce"]),
    "firewall": firewall,
    "ssh_policy": ssh_policy(*(sys.argv[2:] + ["", "", ""])[:3]),
    "privileged_access": privileged_access(),
}))
