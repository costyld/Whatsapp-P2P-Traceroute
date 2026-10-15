"""Live web dashboard: FastAPI + WebSocket feed + offline Leaflet map.

Runs the sniffer in a background thread and streams enriched flow records to
connected browsers. Serves a single self-contained HTML page.
"""
import asyncio
import logging
import threading
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

import config
from core.packet_sniffer import PacketSniffer
from core.meta_ranges import refresh_ranges
from core.ip_filter import load_networks
from core.reporting import write_reports
from utils.helpers import setup_logging, ensure_dirs

log = setup_logging()
app = FastAPI(title="WhatsApp IP Tracker")

INDEX = Path(__file__).parent / "static" / "index.html"

_clients: set[WebSocket] = set()
_loop: asyncio.AbstractEventLoop | None = None
_sniffer: PacketSniffer | None = None
_capture_options = {"iface": config.DEFAULT_IFACE, "count": config.DEFAULT_COUNT, "timeout": None}
_no_refresh = False


def _broadcast(record: dict):
    """Called from the sniffer thread; hands the record to the asyncio loop."""
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(_push(record), _loop)


async def _push(record: dict):
    dead = []
    for ws in _clients:
        try:
            await ws.send_json(record)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _clients.discard(ws)


def _run_sniffer():
    global _sniffer
    load_networks(config.WHATSAPP_IP_RANGES if _no_refresh else refresh_ranges())
    _sniffer = PacketSniffer(on_record=_broadcast)
    try:
        _sniffer.start_sniffing(**_capture_options)
    except PermissionError:
        log.error("Capture failed: need Administrator/root privileges.")
    except Exception as e:
        log.error("Capture stopped: %s", e)


@app.on_event("startup")
async def _startup():
    global _loop
    ensure_dirs()
    _loop = asyncio.get_running_loop()
    threading.Thread(target=_run_sniffer, daemon=True).start()
    log.info("Dashboard ready at http://%s:%d", config.DASH_HOST, config.DASH_PORT)


@app.on_event("shutdown")
async def _shutdown():
    if _sniffer and _sniffer.records:
        write_reports([r.to_dict() for r in _sniffer.records])


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX.read_text(encoding="utf-8")


@app.get("/api/report")
async def report():
    if not _sniffer:
        return []
    from core.reporting import aggregate, _serializable

    rows = [_serializable(a) for a in aggregate([r.to_dict() for r in _sniffer.records]).values()]
    rows.sort(key=lambda r: r["max_score"], reverse=True)
    return rows


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    _clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep-alive / ignore
    except WebSocketDisconnect:
        _clients.discard(websocket)


def run(args=None):
    global _capture_options, _no_refresh
    import uvicorn

    if args is not None:
        _capture_options = {"iface": args.iface, "count": args.count, "timeout": args.timeout}
        _no_refresh = args.no_refresh
    uvicorn.run(app, host=config.DASH_HOST, port=config.DASH_PORT, log_level="warning")


if __name__ == "__main__":
    run()
