# Testing and verification

## Safe local checks

```sh
python3 -m unittest discover -v
python3 -m compileall -q nextguard tests
shellcheck install.sh uninstall.sh bin/nextguard bin/ping-control
```

Fixtures use documentation-only addresses and mocks; they do not contact live feeds or modify the host firewall. Unit coverage checks bilingual key parity, atomic config defaults, IPv4/CIDR/comments/duplicates/mixed IPv6, HTML/malformed/default-route rejection, explicit empty contracts, DShield range conversion, Spamhaus formats, exact set-preserving collapse, preservation of a good per-source copy, mixed old/new sources, and prepare-before-swap/DROP-only firewall construction.

## Isolated integration checklist (not run here)

Use a disposable Ubuntu 24.04 VM (preferred for systemd/reboot/UFW/Docker) or a network namespace with isolated netfilter. Never target unrelated systems.

1. Install twice; verify config survives and foreign launchers are rejected. Open a new login shell and run both launchers.
2. Serve fixture responses locally through a test-only catalogue: 200, 304 with/without cache, 404, 429 + Retry-After, 500, timeout, truncated body, HTML, malformed JSON, and documented/undocumented empty responses.
3. Inject ipset restore/swap capacity failures. Confirm active set/generation is unchanged; then recover and apply cache without a content change. Reboot beforehand and confirm the previous generation restores.
4. Race manual and timer updates and kill the updater at each atomic boundary; validate JSON, symlink, and firewall remain coherent.
5. From a peer namespace, test a new connection, an already-established incoming connection after adding its source, and replies to a connection initiated by the protected host. Packet-capture the peer to confirm DROP emits no RST/REJECT/ICMP error.
6. Test input, Docker host mode, and real bridge/published-port `DOCKER-USER` paths. Reload supported UFW and restart NextGuard; check early ordering and no duplicate jumps.
7. Generate intersecting list/ping events and verify all provenance, category filtering without DROP changes, single event per packet, bounded sampling, rotation, logger failure independence, and firewall counters.
8. Start/restart/stop ping repeatedly. Confirm one owned rule, only IPv4 echo-request is affected, and other ICMP/IPv6 remain unchanged.
9. Uninstall and verify foreign rules, policy, Docker rules/containers, packages, and retained data are untouched.

These integration scenarios are prepared but are **not claimed as passed** unless their commands and environment are recorded in a release report.
