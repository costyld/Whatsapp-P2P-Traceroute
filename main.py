"""WhatsApp IP Tracker — CLI entrypoint.

AUTHORIZED / EDUCATIONAL USE ONLY. Capture only traffic on networks you own or
have explicit permission to monitor. Using this to deanonymize or track a person
without consent may be illegal (privacy/anti-stalking laws).
"""
import argparse
import sys

import config
from core.packet_sniffer import PacketSniffer
from core.meta_ranges import refresh_ranges
from core.ip_filter import load_networks
from core.reporting import write_reports
from utils.helpers import setup_logging, ensure_dirs, require_admin
from utils.geo_ip import close as close_geo


def build_parser():
    p = argparse.ArgumentParser(description="WhatsApp IP Tracker (authorized use only)")
    p.add_argument("--iface", default=config.DEFAULT_IFACE, help="Interface to sniff (blank = auto)")
    p.add_argument("--count", type=int, default=config.DEFAULT_COUNT, help="Packet count (0 = until Ctrl+C)")
    p.add_argument("--timeout", type=int, default=None, help="Stop after N seconds")
    p.add_argument("--no-refresh", action="store_true", help="Skip online Meta-range refresh")
    p.add_argument("--dashboard", action="store_true", help="Launch live web dashboard instead of CLI")
    return p


def run_cli(args, log):
    require_admin(log)
    ranges = config.WHATSAPP_IP_RANGES if args.no_refresh else refresh_ranges()
    load_networks(ranges)

    sniffer = PacketSniffer()
    try:
        sniffer.start_sniffing(iface=args.iface, count=args.count, timeout=args.timeout)
    except PermissionError:
        log.error("Capture failed: run as Administrator/root.")
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Interrupted; saving captured data.")
        sniffer.save_packets()

    records = [r.to_dict() for r in sniffer.records]
    if records:
        rows = write_reports(records)
        peers = [r for r in rows if r["candidate_peer"]]
        log.info("Done. %d unique remotes, %d candidate peer(s).", len(rows), len(peers))
        for r in peers[:10]:
            log.info("  PEER? %s %s %s", r["remote"], r["org"], r["country"])
    else:
        log.info("No WhatsApp/Meta traffic captured.")
    close_geo()


def main():
    log = setup_logging()
    ensure_dirs()
    args = build_parser().parse_args()

    if args.dashboard:
        from dashboard.server import run
        require_admin(log)
        run(args)
    else:
        run_cli(args, log)


if __name__ == "__main__":
    main()
