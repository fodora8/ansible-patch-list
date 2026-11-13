# Full v3 deployment for Red Hat Enterprise Linux

Full v3 runs from the Ansible controller and publishes a paginated HTML report, host detail pages, CVE lookups, and a fleet CSV. Full v3 currently runs on demand.

## Controller deployment

1. Use a Linux controller with Ansible Core, OpenSSH client, Python 3.9 or later, and `flock` from util-linux. Use Lighttpd or Nginx to serve the generated files.
2. Put `collect-full-v3.yml`, `snapshots.json.j2`, and an `inventory.yml` based on [the RHEL example](inventory-rhel.example.yml) in `/opt/security-report`. Put `collect.py`, `render.py`, and `report.html` in its `full-v3/` subdirectory.
3. In inventory, set `report_state_dir` to a private directory writable by the reporting user and `report_web_dir` to the report server's document root. The example uses `/var/lib/security-report` and `/usr/share/nginx/html/security-report`. The playbook creates `full-v3/` under the web root. Keep the private state directory outside that root.
4. Serve the report directory under `/full-v3/` using the existing report server's access rules. On Lighttpd, set `report_web_dir` to the virtual host's document root, ensure `index.html` is an index file, and include [the metrics configuration](lighttpd-metrics.conf) in that virtual host. Validate with `lighttpd -tt -f /etc/lighttpd/lighttpd.conf` before reloading. On Nginx, include `full-v3/nginx-locations.conf` in the existing report server block and validate with `nginx -t` before reloading.
5. Add targets to `report_targets` and run the playbook as the reporting account.

```bash
cd /opt/security-report
ansible-playbook -i inventory.yml collect-full-v3.yml
```

The controller writes `snapshots-full-v3.json` with mode `0600`. It renders host detail pages and a small JSON file per CVE, publishes the new HTML and CSV, and retains the two most recent generations of host and CVE files. The browser fetches a CVE file only when a full CVE ID is searched, and fetches a host detail page when a host is opened. The main HTML and its lookups use the same generation. In a 4,500-host simulation, the main HTML was **746 KB** and a CVE lookup matching 3,000 hosts was **14 KB**, both uncompressed.

## Target deployment and collection

Each target needs a reachable SSH service, a reporting login authorised with the controller's public key, non-interactive sudo for this playbook, and a working Python interpreter. Keep the private key on the controller and pin the target's SSH host key there. Set the inventory address, account, expected listener list, and any interpreter override. The example uses `/usr/bin/python3`. Set `report_python` when your RHEL installation provides Python 3 at a different path. Use `report_ssh_client_hostname` where the SSH policy depends on a hostname in a `Match Host` rule.

Ansible first reads `SSH_CONNECTION` through the management login. It then uploads `full-v3/collect.py` to a temporary path, runs it with sudo, returns a JSON record, and normally removes the temporary script. SSH and sudo may write their usual logs. The playbook uses the target's existing services and tools and installs no persistent agent. Collection does not install updates, reboot hosts, restart services, or change their configuration.

| Check | What runs on the target |
|---|---|
| OS, kernel, boot and uptime | Reads `/etc/os-release` and `/proc`, and reads the running kernel release. |
| Virtualisation and SELinux | Runs `systemd-detect-virt` and `getenforce`. |
| Listening sockets and services | Runs `ss -lntup` and queries systemd for running services and failed units. The report compares local listeners with the inventory baseline. |
| Host firewall | Reads firewalld state and zones, or reads the rules with `nft list ruleset`, `iptables-save`, and `ip6tables-save` where available. |
| Effective SSH policy | Runs `sshd -T -C` against the standard on-disk configuration for root and the collection account, using the management connection's address and port context. |
| Local privileged access | Reads local UID 0 accounts and `wheel` and `sudo` memberships. It reads standard sudoers files to compute fingerprints in the private snapshot. The published report lists file paths. |
| Security advisories and CVEs | Lists enabled repositories and compares installed packages with Red Hat Security Advisory metadata available to the host. Hosts without working DNF advisory access report unavailable advisory data. |
| Reboot status | Runs `needs-restarting -r` where available. The DNF form disables all repositories for this check. |

## DNF refresh and repository impact

RHEL hosts need access to entitled Red Hat CDN content, their assigned Satellite content, or an approved internal mirror that publishes advisory metadata. Full v3 uses each host’s enabled DNF repositories and existing subscription configuration. The report reflects the content visible to that host. [Red Hat guidance on identifying security updates](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_and_monitoring_security_updates/identifying-security-updates_managing-and-monitoring-security-updates)

`dnf repolist --enabled` lists enabled repositories. The collector then runs `dnf --refresh updateinfo list updates security`, which forces DNF to revalidate repository metadata for that host. If the metadata changed or the local cache is empty, DNF downloads the metadata it needs and updates its local cache. The report refresh makes metadata requests and does not download update RPMs. After the advisory query succeeds, the CVE query uses `--cacheonly`, so it adds local CPU and disk work without a second repository refresh. [DNF command reference](https://dnf.readthedocs.io/en/latest/command_ref.html)

The aggregate load depends on how many hosts share each repository, how many repositories each host uses, whether metadata changed, and how many collectors run at once. A warm run can mostly revalidate metadata. A run after repository publication or cache eviction can make many hosts download the same data. An HTTPS CONNECT proxy without caching forwards that traffic upstream. For an internal mirror or Satellite, measure the traffic against the endpoint the hosts actually use.

For capacity planning, if all 4,500 hosts each transfer an average of **1 MB**, **10 MB**, or **50 MB** of metadata, the combined download is about **4.5 GB**, **45 GB**, or **225 GB** respectively, in decimal units. These are examples, not lab measurements. Averages also hide bursts against a shared mirror or proxy. In a pilot, measure metadata bytes, request rates, repository errors, and host collection time before increasing concurrency. The advisory command has a **180-second timeout per host**. The repository-list and cache-only CVE commands have separate limits of 30 and 60 seconds. Advisory failures appear as unavailable data and can occupy a worker much longer than a normal run.

## Completion estimate for 4,500 hosts

A three-host engineering benchmark completed in **5.4 seconds** with existing caches, including SSH context gathering and rendering. This was a concurrent lab run. Production RHEL performance and a live 4,500-host collection remain to be measured.

The deployed controller defaults to **five forks**. The collection task has `throttle: 10`, so `-f 10` raises effective collection concurrency to ten. Ansible uses the linear strategy and finishes the SSH context task before starting the collector task. [Ansible execution and concurrency](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_strategies.html)

| Combined average worker time per host | 5 concurrent workers | 10 concurrent workers |
|---|---:|---:|
| 4–5 seconds | 60–75 minutes | 30–38 minutes |
| 10 seconds | 2 hours 30 minutes | 1 hour 15 minutes |
| 20 seconds | 5 hours | 2 hours 30 minutes |

The estimates divide host count × average worker time by concurrency and exclude final rendering. Allow **2–3 hours at ten workers** as an initial planning window, subject to a representative pilot of **100–200 hosts** across repositories, network segments, and cache states. Use the measured throughput and slow-host behaviour to set the job timeout. For a pilot, use a separate inventory and output directories so its partial result cannot replace the full fleet report. The older report's 30-minute systemd timeout is not suitable as a Full v3 fleet default.

## Prometheus and Grafana

Full v3 generates a static Prometheus text file alongside the CSV. The web server serves it at `/full-v3/metrics` under the same access rules as the report. Scrapes only read the last published file and do not start Ansible or contact the monitored hosts.

Merge the job from [the scrape example](prometheus-scrape.example.yml) into the existing Prometheus `scrape_configs` list, and set the target to the report server. The example uses a placeholder hostname and a 15-minute interval. Use the existing Grafana Prometheus data source to query the metrics. From the Prometheus server, check that the endpoint returns HTTP 200 and `Content-Type: text/plain; version=0.0.4`, optionally with a charset parameter.

```sh
curl -fsSI http://reports.example.com/full-v3/metrics
```

[Lighttpd MIME configuration](https://redmine.lighttpd.net/projects/lighttpd/wiki/Mimetype_assignDetails) · [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/)

| Grafana panel | PromQL |
|---|---|
| Hosts by report status | `fleet_security_hosts{job="fleet-security-full-v3"}` |
| Critical advisories by host | `fleet_security_pending_advisories{job="fleet-security-full-v3",severity="critical"}` |
| Hosts missing advisory data | `fleet_security_host_status{job="fleet-security-full-v3"} unless on(job,instance,host) fleet_security_pending_advisories{job="fleet-security-full-v3",severity="critical"}` |
| Report age in hours | `(time() - fleet_security_report_generated_timestamp_seconds{job="fleet-security-full-v3"}) / 3600` |

Host status codes are 0 for OK, 1 for Review, 2 for Urgent, 3 for Unknown, and 4 for Unreachable. The per-host collection timestamp records when the host was last observed in the current report. Unknown numeric checks are omitted. A successful HTTP scrape can still return an old report, so use the report age alongside Prometheus's `up` metric. Individual CVE IDs and detailed findings remain available in the HTML report.

The exporter emits at most ten samples per host and six fleet samples per scrape. At 4,500 hosts, the upper bound is 45,006 samples per scrape or roughly 50 samples per second averaged over a 15-minute interval. The number drops when host data is unavailable.
