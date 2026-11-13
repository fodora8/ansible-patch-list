# Full v3 report for RHEL

Run as the reporting account on the controller.

```sh
cd /opt/security-report
ansible-playbook -i inventory.yml collect-full-v3.yml
```

Copy the contents of this directory, including its nested `full-v3/` directory, to
`/opt/security-report`. Include `full-v3/nginx-locations.conf` inside the existing report
server block so the routes inherit the same access rules. The playbook writes
`snapshots-full-v3.json` under the report state directory and serves output under
`/full-v3/`. The collector uses the target’s enabled RHEL repositories and checks SSH
policy and local privileged access. See the [deployment guide](DEPLOYMENT.md)
and [example inventory](inventory-rhel.example.yml).

The main page includes the host summary. A complete CVE ID loads one lookup file
for the same report generation as the page. Host details also load from that
generation. The renderer retains the latest two generations.
