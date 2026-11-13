# Full v3 report for RHEL

Run as the reporting account on the controller.

```sh
cd /opt/security-report
ansible-playbook -i localhost, collect-full-v3.yml
```

Copy the contents of this directory, including its nested `full-v3/` directory, to
`/opt/security-report`. See the [deployment guide](DEPLOYMENT.md) for Lighttpd and Nginx setup. The playbook writes
`snapshots-full-v3.json` under the report state directory and serves output under
`/full-v3/`. The collector uses the target’s enabled RHEL repositories and checks SSH
policy and local privileged access. See the [deployment guide](DEPLOYMENT.md)
and [example host list](hosts.example.txt).

The controller reads `hosts.txt` once per run. The file contains only hostnames or
IPv4 addresses. Blank lines are ignored and duplicates are collapsed. The
`localhost,` argument supplies the controller inventory entry. To use a dump at
another controller path, pass `-e report_hosts_file=/path/to/hosts.txt`. Have the
dump producer write to a temporary file and rename it into place so the
playbook reads a complete list. The daily timer reads the same file each time.

The main page includes the host summary. A complete CVE ID loads one lookup file
for the same report generation as the page. Host details also load from that
generation. The renderer retains the latest two generations.
