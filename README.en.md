# NextGuard

English · [Русский](README.md)

**NextGuard** is a host-installed incoming IPv4 filter driven by curated IP/CIDR lists. It strictly validates downloads, atomically swaps one `ipset`, and uses only `DROP` rules in owned `iptables` chains. Developer: **@artemkaa_2001**.

> NextGuard neither filters nor changes IPv6 and creates no ip6tables rules. IPv6 traffic is not protected. DROP sends no RST, REJECT, or ICMP error; the remote peer waits for its own timeout.

## Modules

| Module | Behavior |
|---|---|
| RKN and related scanners | Blocks specialist-source entries. Lists can contain author observations or broad organization networks; a match does not prove ownership of every IP. |
| Known attackers, DDoS | Blocks known addresses from suitable feeds. This is **not a DDoS detector** and cannot stop unknown botnets or upstream saturation. |
| Other scanners | Blocks published IPv4 networks of internet-scanning organizations. |
| Block ping | Independently blocks only incoming IPv4 ICMP echo-request. Other ICMP and IPv6 remain untouched. |

One listing is sufficient for immediate blocking. Removal from one source does not unblock an address still present elsewhere; removal from all active copies removes only NextGuard's prohibition. There is no scoring, learning, DPI, WAF, honeypot, or log-driven banning.

## Install and operate

The supported target is **Ubuntu 24.04 LTS with systemd, iptables (including its nft backend), ipset, and Python 3**. Other distributions are not claimed. No Docker, account, management port, web panel, or remote controller is required.

Review a local checkout, then run:

```sh
sudo ./install.sh
sudo nextguard
```

The installer uses apt only when ipset/iptables are absent, preserves configuration on reinstall, and refuses to overwrite foreign `nextguard`/`guard` commands. Available commands are `nextguard`, `status`, `update`, `logs`, `uninstall`, `--help`, `--version`, and `--lang ru|en`; `guard` is an equivalent launcher. Mutating operations explain the need for sudo. Piped installs use `/dev/tty` and fail helpfully rather than hanging when none exists. EOF/Ctrl+C or exiting before Apply leaves active settings unchanged.

The actual menu includes independently toggled modules, 30/60-minute period, per-category logging, language, status, update, apply, recent logs, and confirmed removal.

## Updates and safety

The timer checks feeds every 30 or 60 minutes while respecting a source's longer minimum. The downloader uses verified TLS, timeout, a 32 MiB limit, conditional ETag/Last-Modified requests, and correct 304 handling. HTML, malformed documents/CIDRs, `0.0.0.0/0`, and unexpectedly empty responses are rejected as a whole; IPv6 is skipped with its own counter. A failed source retains its own last valid copy indefinitely. A first-time failure is reported as incomplete coverage.

Normalization only merges exactly equivalent adjacent ranges and never expands membership; provenance remains separate. A temporary ipset is completely populated before `swap`. The generation pointer changes only after firewall success, two generations are retained, and `flock` serializes updates. Boot restoration uses the last applied local generation without requiring the Internet.

## Firewall, containers, and logs

NextGuard never flushes the ruleset, changes global policy/UFW, or deletes foreign rules. Its INPUT jump precedes broad ACCEPT/ESTABLISHED rules. Replies to server-initiated traffic are not destination filtering. If Docker already provides `DOCKER-USER`, its bridge/published traffic gets the same early jump; host networking uses INPUT. Docker is never installed or configured. Real Docker/UFW/reboot integration was not executable in this environment; restart `nextguard.service` after a UFW reload. Interface scope is configurable; empty means all interfaces.

Behind a CDN/proxy the firewall sees the network peer, not an HTTP forwarded-client header. This ipset layer cannot promise filtering of that header's client.

Rate-limited kernel logs (10/s, burst 20) go to journald. The logger uses active local provenance, writes localized `/var/log/nextguard/events.log`, groups repeats for five seconds, bounds its cache, and rotates at 10 MiB with five archives. These are sampled messages, not an exact total; firewall counters are shown by `status`. Category selection affects logging only, never DROP. Logger failure cannot disable filtering.

The ping unit owns only its chain and is idempotent. List matching precedes ping matching to preserve provenance. Disabling it cannot guarantee replies through another firewall/provider, and ping silence does not hide an open TCP port.

## Removal, diagnosis, and tests

`sudo nextguard uninstall` requires explicit confirmation and removes only owned units, jumps, chains, set, and symlinks. It leaves packages, foreign firewall state, configuration, caches, and logs. Thus removal does not mean all ports become open.

`status` reports each source's timestamps, error, IPv4 and skipped-IPv6 count. A 429 keeps the old copy. An apply failure leaves the applied generation unchanged and a later update retries cached data.

```sh
python3 -m unittest discover -v
python3 -m compileall -q nextguard tests
shellcheck install.sh uninstall.sh bin/nextguard bin/ping-control
```

Run network behavior tests only in a disposable VM or namespace. No feed snapshots, secrets, or user logs are shipped. See [SOURCES.md](SOURCES.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and [TESTING.md](TESTING.md).

NextGuard's original code is MIT licensed; downloaded data retains separate provider terms. This record is not legal advice or a legal guarantee.
