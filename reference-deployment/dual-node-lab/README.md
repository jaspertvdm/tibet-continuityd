# dual-node-lab

Deze map is de eerste reference-opzet voor host-to-host continuity
gedrag zonder meteen zware orchestration.

Doel:

- `node-a` ontvangt een geldige sealed bundle
- `node-a` doet `sniff -> verify-fork -> seal`
- bridge zet `node-a/outbox/*.tza` door naar `node-b/inbox`
- `node-b` verwerkt die doorgifte opnieuw
- audits en output worden naast elkaar leesbaar

## Wat dit al bewijst

- outbox van A kan als inbox voor B dienen
- beide nodes kunnen dezelfde format-family verwerken
- stage-verdeling en surface-hash/disposition gedrag zijn vergelijkbaar
- handoff is reproduceerbaar in een simpele lab-opzet

## Wat dit nog niet claimt

- geen volledige netwerkstack
- geen mux/protocol transport
- geen formele cross-host continuity resume waarbij `continuity_id`
  end-to-end identiek blijft

Dus:

- dit is een **handoff lab**
- nog niet de definitieve **cross-host lineage import discipline**

## Bestanden

- `RUNBOOK.md`
- `prepare-lab.sh`
- `run-lab-demo.sh`
- `start-lab.sh`
- `stop-lab.sh`
- `inject-demo.sh`
- `bridge-a-to-b.sh`
- `compare-audit.sh`
- `show-status.sh`

## Kernidee

Begin met een eenvoudige bridge:

- copy/rsync/shared directory

Niet meteen:

- containers
- echte network mux
- service mesh

Dat maakt de eerste dual-node proef herhaalbaar op één host, twee VM's
of later twee containers.
