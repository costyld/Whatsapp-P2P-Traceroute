"""Packet capture engine (TCP + UDP), interface auto-detect, live callback."""
import logging
import threading

from scapy.all import AsyncSniffer, wrpcap, get_working_ifaces, conf, get_if_addr
from scapy.arch import in6_getifaddr

import config
from core.classifier import classify
from core.history import HistoryStore

log = logging.getLogger("wit")


def pick_interface(requested: str = "") -> str:
    """Return a usable interface name. Auto-detect when none requested."""
    if requested:
        return requested
    try:
        name = conf.route.route("0.0.0.0")[0]
        if name and name not in ("lo", "lo0"):
            log.info("Auto-selected default-route interface: %s", name)
            return name
        ifaces = get_working_ifaces()
        ifaces = [i for i in ifaces if getattr(i, "name", str(i)) not in ("lo", "lo0")]
        if ifaces:
            name = getattr(ifaces[0], "name", str(ifaces[0]))
            log.info("Auto-selected interface: %s", name)
            return name
    except Exception as e:
        log.debug("Interface auto-detect failed: %s", e)
    return "eth0"  # last resort


class PacketSniffer:
    def __init__(self, log_file=None, on_record=None, history_enabled=True):
        self.log_file = str(log_file or config.LOG_FILE)
        self.packets = []          # raw packets for pcap
        self.records = []          # enriched FlowRecords
        self.on_record = on_record  # optional callback(record_dict) for live feed
        self.local_ips = None
        self.history_enabled = history_enabled
        self.history = None
        self.capture_id = None
        self._stop = threading.Event()

    def process_packet(self, packet):
        record = classify(packet, local_ips=self.local_ips)
        if record is None:
            return
        self.packets.append(packet)
        self.records.append(record)
        if self.history:
            self.history.record(self.capture_id, record.to_dict())
        tag = "PEER?" if record.candidate_peer else ("META" if record.is_meta else "REMOTE")
        log.info(
            "[%s] %s %s:%d -> %s:%d %s %s",
            tag, record.proto, record.src, record.sport,
            record.dst, record.dport, record.org, record.country,
        )
        if self.on_record:
            try:
                self.on_record(record.to_dict())
            except Exception as e:
                log.debug("on_record callback error: %s", e)

    def start_sniffing(self, iface="", count=0, timeout=None):
        iface = pick_interface(iface)
        self.local_ips = {get_if_addr(iface)}
        self.local_ips.update(a for a, scope, name in in6_getifaddr() if name == iface)
        log.info("Starting capture on %s (filter=%r, count=%s)", iface, config.BPF_FILTER, count or "∞")
        capture = AsyncSniffer(iface=iface, filter=config.BPF_FILTER,
                               prn=self.process_packet, count=count, timeout=timeout, store=False)
        status = "finished"
        try:
            if self.history_enabled:
                self.history = HistoryStore(config.HISTORY_DB, config.SESSION_IDLE_SECONDS)
                self.capture_id = self.history.start_capture(iface)
                log.info("History capture: %s", self.capture_id)
            capture.start()
            # join() propagates capture-thread errors; bounded joins let shutdown
            # stop an idle interface without waiting for another packet.
            while capture.thread.is_alive():
                if self._stop.is_set() and capture.running and hasattr(capture, "stop_cb"):
                    status = "interrupted"
                    capture.stop()
                capture.join(timeout=0.25)
            capture.join()
        except KeyboardInterrupt:
            status = "interrupted"
            raise
        except Exception:
            status = "failed"
            raise
        finally:
            try:
                if capture.thread and capture.thread.is_alive() and capture.running and hasattr(capture, "stop_cb"):
                    capture.stop()
            finally:
                if self.history:
                    try:
                        self.history.finish_capture(self.capture_id, status)
                    finally:
                        self.history.close()
                        self.history = None
                self.save_packets()

    def stop(self):
        self._stop.set()

    def save_packets(self):
        if not self.packets:
            log.info("No packets captured; nothing to save.")
            return
        log.info("Saving %d packets to %s", len(self.packets), self.log_file)
        wrpcap(self.log_file, self.packets)
