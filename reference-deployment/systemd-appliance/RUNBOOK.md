# systemd Appliance Runbook

## Doel

Een proef-VM opzetten waarop `tibet-continuityd` resident draait en
de bekende continuity fixtures kan verwerken.

## Voorwaarden

- Linux VM met `systemd`
- `python3`
- lokale checkout van `/srv/jtel-stack`
- rechten om directories onder `/var/lib/tibet` en `/var/log/tibet`
  aan te maken

## Stap 1 — prepare

```bash
bash prepare-appliance.sh
```

Dit maakt:

- lane-directories onder `/var/lib/tibet`
- audit-locatie onder `/var/log/tibet`
- runtime env-bestand:
  - `/tmp/tibet-continuityd-appliance.env`

## Stap 2 — installeer service

Reference pad:

```bash
sudo cp tibet-continuityd.service /etc/systemd/system/
sudo mkdir -p /etc/tibet
sudo cp continuityd.env.example /etc/tibet/continuityd.env
```

Pas daarna in de service aan:

- `EnvironmentFile=/etc/tibet/continuityd.env`
- `ExecStart` naar de juiste `PYTHONPATH`/checkout op de host

## Stap 3 — start appliance

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tibet-continuityd
sudo systemctl status tibet-continuityd --no-pager
```

## Stap 4 — drop demo fixtures

```bash
bash drop-demo-fixtures.sh
```

Verwachte hoofdlijn:

- sealed fixture → `trusted-candidate` of verdere pipeline-route
- disguised fixture → triage-achtige route
- json fixture → reseal/observe
- executable fixture → quarantine/strict reject
- pdf fixture → reject/strict reject

## Stap 5 — audit lezen

```bash
bash show-audit-summary.sh
```

En indien gewenst:

```bash
sudo journalctl -u tibet-continuityd -n 100 --no-pager
```

## Stap 6 — service status en lanes

```bash
bash show-status.sh
```

## Succescriteria

- service start zonder crash
- auditbestand groeit
- lanes bestaan en reageren logisch
- shutdown via `systemctl stop tibet-continuityd` is schoon

## Niet in deze fase

- package-install via pip/wheel
- automatische system-user provisioning
- multi-node handoff
- kernel sysctl tuning voor inotify overflow
