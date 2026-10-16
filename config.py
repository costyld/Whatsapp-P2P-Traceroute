"""Central configuration.

Values are read from environment variables (see .env.example) with sane
defaults so the tool runs out of the box for authorized/educational use.
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # python-dotenv optional
    pass

# --- Paths -----------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
OUTPUT_DIR = BASE_DIR / "output"
DATA_DIR = BASE_DIR / "data"

LOG_FILE = LOG_DIR / "packet_logs.pcap"
CSV_REPORT = OUTPUT_DIR / "ip_report.csv"
JSON_REPORT = OUTPUT_DIR / "ip_report.json"
HISTORY_DB = Path(os.getenv("WIT_HISTORY_DB", str(DATA_DIR / "history.sqlite3")))
SESSION_IDLE_SECONDS = int(os.getenv("WIT_SESSION_IDLE_SECONDS", "60"))

# GeoLite2 databases (download from MaxMind, free account).
GEO_CITY_DB = os.getenv("GEO_CITY_DB", str(DATA_DIR / "GeoLite2-City.mmdb"))
GEO_ASN_DB = os.getenv("GEO_ASN_DB", str(DATA_DIR / "GeoLite2-ASN.mmdb"))

# --- Capture settings ------------------------------------------------------
# Empty string => scapy auto-selects a working interface.
DEFAULT_IFACE = os.getenv("WIT_IFACE", "")
DEFAULT_COUNT = int(os.getenv("WIT_COUNT", "0"))  # 0 = capture until stopped
# Both protocols: WhatsApp uses UDP (RTP/STUN media) and TCP (443/5222 signaling).
BPF_FILTER = os.getenv("WIT_BPF", "udp or tcp")

# --- Meta / WhatsApp networks ---------------------------------------------
# Seed ranges. Refreshed at runtime from Meta's published prefix list for
# AS32934 when network access is available (see core.meta_ranges).
WHATSAPP_IP_RANGES = [
    "31.13.24.0/21",
    "31.13.64.0/18",
    "66.220.144.0/20",
    "69.63.176.0/20",
    "69.171.224.0/19",
    "74.119.76.0/22",
    "103.4.96.0/22",
    "129.134.0.0/17",
    "157.240.0.0/16",
    "173.252.64.0/18",
    "179.60.192.0/22",
    "185.60.216.0/22",
    "204.15.20.0/22",
    "2a03:2880::/32",
]

META_ASN = 32934  # Meta Platforms / Facebook

# Cache of the auto-refreshed prefix list.
META_RANGE_CACHE = DATA_DIR / "meta_ranges.json"
META_RANGE_MAX_AGE_HOURS = int(os.getenv("WIT_RANGE_MAX_AGE", "24"))

# --- Dashboard -------------------------------------------------------------
DASH_HOST = os.getenv("WIT_HOST", "127.0.0.1")
DASH_PORT = int(os.getenv("WIT_PORT", "8000"))
