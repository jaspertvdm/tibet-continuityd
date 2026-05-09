# systemd-appliance

Deze map is de reference-opzet voor een proef-VM waarop
`tibet-continuityd` als resident subsystem draait.

Doel:

- daemon onder `systemd`
- vaste lane-layout
- eenvoudige operatorflow
- reproduceerbare proefinstallatie

## Bestanden

- `RUNBOOK.md`
  - stap-voor-stap proefinstallatie
- `tibet-continuityd.service`
  - reference unit voor de appliance
- `continuityd.env.example`
  - voorbeeld-omgeving voor de unit
- `prepare-appliance.sh`
  - maakt directories en schrijft runtime-env
- `drop-demo-fixtures.sh`
  - dropt de bekende fixture-set in de inbox
- `show-audit-summary.sh`
  - toont een compacte audit-samenvatting
- `show-status.sh`
  - laat service- en lane-status zien

## Scope van deze reference-opzet

Deze appliance is bedoeld voor:

- VM-proeven
- operator demo's
- resident continuityd gedrag

Niet voor:

- volledige productiehardening
- package install automation
- multi-node orchestration

## Verwachte lane-layout

- `/var/lib/tibet/inbox`
- `/var/lib/tibet/quarantine`
- `/var/lib/tibet/triage`
- `/var/lib/tibet/outbox`
- `/var/lib/tibet/outbox.staging`
- `/var/log/tibet/continuityd-audit.jsonl`

## Bedoelde volgorde

1. `prepare-appliance.sh`
2. installeer unit + env
3. `systemctl enable --now tibet-continuityd`
4. `drop-demo-fixtures.sh`
5. `show-audit-summary.sh`
