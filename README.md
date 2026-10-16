# WhatsApp P2P Traceroute

A network traffic analyzer for **WhatsApp / Meta** flows. It captures packets on
an interface you control, filters traffic belonging to Meta's network
(AS32934), enriches every remote endpoint with **geolocation, ASN, and
reverse-DNS**, and flags **candidate peer-to-peer endpoints** — the non-Meta
public IPs seen during media traffic that are the only realistic way passive
capture can surface a real peer instead of a relay server.

> ⚠️ **Authorized / educational use only.**
> Capture only traffic on networks you own or have explicit permission to
> monitor. Using this to locate or deanonymize a person without consent may
> violate privacy and anti-stalking laws. You are responsible for lawful use.

---

## Reality check (read this first)

Modern WhatsApp voice/video calls are usually **relayed through Meta's TURN
servers**, so most IPs you capture are Meta's, not the other person's. A direct
peer IP only leaks in narrow peer-to-peer situations. This tool surfaces those
as `candidate_peer` records, but there is **no guarantee** any appear. Treat
"get someone's IP from WhatsApp" as mostly a myth — this project is a
traffic-analysis and learning tool, not a locator.

---

## Features

- **TCP + UDP capture** — signaling (443 / 5222) *and* media/STUN (UDP), not
  UDP-only.
- **Auto interface detection** — picks a working NIC automatically, or pass one
  explicitly with `--iface`.
- **Live Meta prefix refresh** — pulls the current AS32934 prefix list from
  RIPEstat (public BGP data), caches it for 24h, and falls back to a bundled
  seed list when offline. No more stale hardcoded ranges.
- **Geo + ASN enrichment** — MaxMind GeoLite2 City + ASN; database readers are
  opened once and results are LRU-cached. Degrades gracefully if the DBs are
  absent (no crash, just blank location).
- **Reverse-DNS labeling** — resolves hostnames and tags Meta-owned domains
  (`whatsapp`, `fbcdn`, `facebook`, …).
- **Peer heuristic scoring** — classifies each flow as **Meta relay**,
  **Remote**, or **candidate P2P peer** and scores it 0–100.
- **CSV + JSON reports** — per-IP aggregation (packets, bytes, ports, protocols,
  first/last seen, geo, ASN), ranked by score.
- **PCAP logging** — raw matched packets saved to `logs/packet_logs.pcap` for
  offline analysis in Wireshark.
- **Live web dashboard** — FastAPI + WebSocket, self-contained offline page with
  a geo map, live packet feed, and a ranked-remotes table.
- **Packaged & tested** — `pyproject.toml`, Docker support, and a `pytest` suite.

---

## Requirements

- **Python 3.10+**
- **Npcap** (Windows) or **libpcap** (Linux/macOS) — required for packet capture.
  Windows: install from [npcap.com](https://npcap.com).
- **Administrator / root** privileges to capture.
- *(Optional)* MaxMind **GeoLite2-City** and **GeoLite2-ASN** databases for
  location/ASN data — free account at
  [maxmind.com](https://www.maxmind.com/en/geolite2/signup).

---

## Install

```bash
git clone https://github.com/arshadakl/Whatsapp-P2P-Traceroute.git
cd Whatsapp-P2P-Traceroute

pip install -r requirements.txt          # or: pip install -e ".[dev]"
cp .env.example .env                      # optional tuning

# Optional: enable location/ASN data
#   download GeoLite2-City.mmdb + GeoLite2-ASN.mmdb into ./data/
```

---

## Usage

Run from an **elevated** terminal (Administrator on Windows, `sudo` on
Linux/macOS).

### CLI capture

```bash
# Capture 500 packets then write reports
python main.py --count 500

# Capture on a specific interface for 60 seconds
python main.py --iface "Wi-Fi" --timeout 60

# Run until Ctrl+C (count 0 = infinite)
python main.py

# Skip the online Meta-range refresh (fully offline)
python main.py --no-refresh
```

### Live dashboard

```bash
python main.py --dashboard
# open http://127.0.0.1:8000
```

Then place a **WhatsApp voice/video call** on a device on the same network and
watch flows appear live.

### Local connection history

Captures now persist aggregate history in `data/history.sqlite3` using SQLite
(no additional dependency). Both CLI and dashboard captures are recorded.
Start a capture normally, or disable history for a capture with:

```bash
python main.py --no-history --timeout 60
python main.py --dashboard --iface en0
```

The dashboard's **Local connection history** panel lets you select captures,
view first/last observations, packet and byte totals, and traffic per minute.
Endpoint totals span captures. Compare two captures to see **added**, **not
seen**, and **shared** IPs. These describe observations, not safety or identity;
an IP may be shared or change, and capture lengths/interfaces affect comparisons.

A session groups one remote IP and protocol **within one capture**. A gap of
60 seconds or more starts a new session. Set `WIT_SESSION_IDLE_SECONDS` to a
positive number to change this; each capture retains its own threshold. Sessions
are activity groupings, not TCP connection lifetimes. No app or person attribution
is performed. Recently observed means the capture is running and the last packet
was within its inactivity threshold.

Use the dashboard's deletion buttons to remove one stopped capture or all stopped
captures. A confirmation is required; this removes history aggregates but does
not remove existing PCAP, CSV, or JSON files. Running captures are protected.
History from an exited process is marked interrupted when next opened in the
history view. Force-killing a process can lose its last uncommitted update; committed
history survives restarts. There is no automatic retention cutoff in this version.

The history database contains endpoint addresses, host labels, observation times,
protocols, and aggregate packet/byte counts, **not packet payloads**. Original PCAP
logging remains separate. `--no-history` disables new history writes, not PCAP
logging or access to previously saved history. Override its path with
`WIT_HISTORY_DB`. The default database and SQLite sidecar files are gitignored.

The UI lists the latest 200 captures/endpoints/sessions and the latest 120 active
minute buckets for the selected capture. Comparison uses all endpoints in the two
selected captures. Capture history starts after installing this feature; existing
JSON/PCAP files are not imported automatically. Restart after changing interfaces
or local addresses. Restrict dashboard access to your local machine (the default).

History API: `GET /api/history`, `GET /api/history/{capture_id}`, and
`GET /api/history/compare?baseline=ID&current=ID`. Deletion uses
`DELETE /api/history/{capture_id}` or `DELETE /api/history` (all stopped captures)
with the `X-History-Action: delete` header; browser requests must be same-origin.

### All options

| Flag           | Default    | Description                              |
|----------------|------------|------------------------------------------|
| `--iface`      | auto       | Interface to sniff (blank = auto-detect) |
| `--count`      | `0`        | Packet count (`0` = until Ctrl+C)        |
| `--timeout`    | none       | Stop capture after N seconds             |
| `--no-refresh` | off        | Skip online Meta-prefix refresh          |
| `--dashboard`  | off        | Launch web dashboard instead of CLI      |

Environment overrides (in `.env`): `WIT_IFACE`, `WIT_COUNT`, `WIT_BPF`,
`WIT_HOST`, `WIT_PORT`, `WIT_RANGE_MAX_AGE`, `GEO_CITY_DB`, `GEO_ASN_DB`.

---

## Output

| File                       | Contents                                             |
|----------------------------|------------------------------------------------------|
| `output/ip_report.csv`     | Per-remote summary, ranked by score                  |
| `output/ip_report.json`    | Same data as JSON                                    |
| `logs/packet_logs.pcap`    | Raw matched packets (open in Wireshark)              |
| `data/meta_ranges.json`    | Cached AS32934 prefix list                           |

**Report columns:** `remote`, `packets`, `bytes`, `protocols`, `ports`,
`is_meta`, `candidate_peer`, `max_score`, `host`, `asn`, `org`, `country`,
`city`, `latitude`, `longitude`, `first_seen`, `last_seen`.

**Flow types:**
- 🟢 **Meta** — endpoint in Meta's network (relay/server). Expected majority.
- 🟡 **Remote** — public non-Meta endpoint, non-media.
- 🔴 **PEER?** (`candidate_peer`) — public non-Meta IP during media traffic;
  possible direct peer. The interesting signal.

---

## Docker

```bash
docker build -t wit .
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 8000:8000 wit --dashboard
```

---

## Tests

```bash
pytest
```

---

## Project structure

```
main.py              CLI entrypoint (capture | --dashboard)
config.py            env-driven settings + seed Meta ranges
core/
  meta_ranges.py     RIPEstat AS32934 prefix auto-refresh + cache
  ip_filter.py       guarded CIDR membership, pre-parsed networks
  classifier.py      packet -> enriched FlowRecord + peer scoring
  packet_sniffer.py  scapy capture, iface auto-detect, live callback
  reporting.py       per-IP aggregation -> CSV/JSON
  dns_resolver.py    cached reverse-DNS + Meta-hostname check
utils/
  geo_ip.py          GeoLite2 city+ASN, open-once, LRU cache
  helpers.py         logging, admin check, dir setup
dashboard/
  server.py          FastAPI + WebSocket server
  static/index.html  offline dashboard (canvas map + live feed)
tests/               pytest suite (ip_filter, classifier, reporting)
```

---

## Troubleshooting

| Symptom                                  | Fix                                                        |
|------------------------------------------|-----------------------------------------------------------|
| `No libpcap provider available`          | Install Npcap (Windows) / libpcap (Linux).                |
| `requires elevated privileges` / exits   | Run terminal as Administrator / use `sudo`.               |
| No packets captured                      | Wrong interface — pass `--iface "Wi-Fi"` explicitly.      |
| Blank city/country/ASN                   | Add GeoLite2 `.mmdb` files to `./data/`.                  |
| Only Meta IPs, no `PEER?`                | Expected — calls are relayed. P2P leak is rare.           |

---

## License

For authorized security research and education. Use responsibly and lawfully.
