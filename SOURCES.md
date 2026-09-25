# Каталог и аудит источников / Source catalogue and audit

Проверка выполнена 2026-09-25 по первичным URL ниже. В текущем окружении исходящий HTTP был заблокирован прокси (`403`), поэтому доступность и содержимое живых файлов **не были повторно подтверждены**; каталог фиксирован и строгий, а runtime-валидатор безопасно сохраняет старую копию при 404/изменении формата. Это технический учёт, не юридическая гарантия. Данные не включаются в git или релиз.

Audit attempted 2026-09-25 against the primary URLs below. This environment's outbound proxy returned `403`, so live availability/content **could not be reconfirmed**. The catalogue is fixed and strict; runtime validation safely retains an old copy after a 404 or format change. This is a technical record, not legal advice. Feed data is never bundled or redistributed.

## Подключённый фиксированный каталог / Configured fixed catalogue

| ID | Модуль / purpose | Файл и формат | Условия / decision |
|---|---|---|---|
| `cyberok_skipa` | RKN-related author observations | [project](https://github.com/tread-lightly/CyberOK_Skipa_ips), [`skipa_cidr.txt`](https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt), lines | No explicit data license established. It is fetched only when the administrator explicitly enables the disabled-by-default RKN module; no redistribution. README caveats about varying confidence are preserved. |
| `spamhaus_drop_v4` | known malicious/networks not to route | [`drop_v4.json`](https://www.spamhaus.org/drop/drop_v4.json), JSON/JSONL; [description](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Used under [DROP Fair Use Policy](https://www.spamhaus.org/blocklists/drop-fair-use-policy/), locally cached, attributed, checked no faster than hourly, not redistributed. DROPv6/eDROP excluded. |
| `blocklist_de_all` | attacker reports | [`all.txt`](https://lists.blocklist.de/lists/all.txt), lines; [export description](https://www.blocklist.de/en/export.html) | Local retrieval under provider [terms](https://www.blocklist.de/en/tou.html), attribution, hourly minimum, no redistribution. |
| `dshield_block` | provider-designated block ranges | [`block.txt`](https://feeds.dshield.org/feeds/block.txt), table; [feed docs](https://isc.sans.edu/feeds_doc.html) | Used with SANS ISC attribution and [published purpose](https://isc.sans.edu/xml.html). Top 100 and All Sources are specifically excluded because they are research sets, not blocklists. |
| `ipsum` | aggregate attacker IPs | [`ipsum.txt`](https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt), IP + count; [project](https://github.com/stamparm/ipsum) | Repository states Unlicense; upstream contributors can retain separate terms. Count is retained as metadata only, never used as a score/threshold. No redistribution. |
| `openfilters_censys`, `openfilters_shodan` | scanner-organization networks | explicit `_v4.txt` files in [OpenFilters/internet-scanners](https://github.com/OpenFilters/internet-scanners/tree/main/cidr) | Repository reported Unlicense. Only explicit IPv4 files are fetched; `.nft`, `inactive`, arbitrary new files, and external code are never executed. Organization labels remain provenance. |

Each `config/sources.json` entry includes stable ID, bilingual names/descriptions, module, HTTPS data/project/terms URL, adapter, empty-list contract, minimum interval, license note, and organization. Runtime metadata adds attempt/success/change timestamps, SHA-256 (local change detection only, not proof of origin), ETag/Last-Modified, current error, counts, and skipped IPv6.

## Изучены, но не подключены / Reviewed candidates not configured

| Candidate | Decision and reason |
|---|---|
| `shadow-netlab/traffic-guard-lists` (`antiscanner.list`, `government_networks.list`, `skipa.list`) | Disabled/excluded pending a confirmed license for data and live format audit. |
| `sngvy/AntiScanner` and separate Gist | Installer repository is GPL-3.0, but that does not establish the Gist data license; mixed categories also require a maintained categorical parser. No code copied, feed excluded. |
| `C24Be/AS_Network_List` | Repository reported BSD-2-Clause, but applicability and current path/content of `blacklist-v4.txt` could not be reconfirmed. Excluded rather than overstating every broad organizational network as an observed scanner. |
| OpenFilters Netlas, FOFA, BinaryEdge, ONYPHE and other `_v4` files | Intended scanner category, but exact current filenames could not be live-audited. Explicit additions can follow after audit; no directory auto-discovery is used. |
| Censys opt-out documentation / CyberOK scan-policy PDF | Documentation-only corroboration; no fragile webpage/PDF scraping. [Censys](https://docs.censys.com/docs/opt-out-of-data-collection), [CyberOK PDF](https://www.cyberok.ru/docs/cyberok_scan_policy_en.pdf). |
| Dataplane signals | Excluded until each stream's purpose, format, and conditions are verified. Normal DNS/NTP observation is not relabeled as DDoS. |
| CrowdSec Community Blocklist | Optional concept only; no adapter. Access can require an account/product/API terms, and NextGuard neither installs the Security Engine nor submits signals. [Terms/docs](https://docs.crowdsec.net/docs/central_api/community_blocklist/). |
| Feodo Tracker, MISP warninglists, VPN/proxy lists, mail DNSBLs | Excluded: their purposes do not automatically make them DDoS/attacker blocklists. |

## Механики изучены без копирования / Mechanics-only references

`dotX12/traffic-guard` (reported MIT), `sngvy/AntiScanner` and `zakachkin/AntiScanner` (reported GPL-3.0), `Balbuto/RKN-Watcher` (reported MIT), `upe4d/tspublock` (no license confirmed), and `pwnnex/ByeByeVPN` (reported GPL-3.0) were candidates for conceptual review only. Their installers/code are not run, bundled, or copied. ByeByeVPN scanning/risk diagnostics and external observation submission are outside scope.

[`ICMP_Toggle.sh`](https://LinuxTools.World/ICMP_Toggle.sh) was referenced for the requested UI attribution only. Its license was not established; no implementation was copied. NextGuard avoids its described duplicate-rule behavior. Absence of a license means no permission to copy, consistent with [Choose a License guidance](https://choosealicense.com/no-permission/).
