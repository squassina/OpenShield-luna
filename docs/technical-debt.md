# Technical debt register

The canonical, prioritized engineering backlog is now maintained in the repository-root [TODO.md](../TODO.md). It is reviewed against the current code and open GitHub issues.

## Open acceptance work

- [Issue #17 — OpenWrt physical hardware and forwarding acceptance](https://github.com/squassina/OpenShield-luna/issues/17)
- [Issue #18 — Live Suricata and Zeek deployment validation](https://github.com/squassina/OpenShield-luna/issues/18)
- [Issue #19 — Representative event load, query plans, and deployment backup/restore](https://github.com/squassina/OpenShield-luna/issues/19)

## Status boundary

P0–P6 software features are implemented to the extent described in README.md. That does not mean the physical gateway, real sensor deployments, production database performance, disaster recovery, or multi-tenant security have been accepted. Synthetic fixtures and CI are necessary regression evidence, not substitutes for deployment evidence.

Historical issues #2, #4–#10, and #13–#15 are closed. Do not treat their original descriptions as current open tasks; follow-up acceptance is captured by #17–#19 and the engineering findings in TODO.md.
