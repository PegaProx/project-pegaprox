"""
PegaProx Syslog Server — receives syslog messages via UDP/TCP
Stores events in SQLite for the integrated log viewer.

NS: Apr 2026 — rewritten for gevent compatibility (no asyncio, no multiprocessing)
Original PR by gyptazy, adapted to fit PegaProx architecture.
"""
import os
import time
import logging
import sqlite3
import threading
from datetime import datetime

from pegaprox.constants import CONFIG_DIR

DB_FILE = os.path.join(CONFIG_DIR, 'syslog.db')

SEVERITY_MAP = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug"
}

_syslog_thread = None


def _open_db(timeout=30):
    conn = sqlite3.connect(DB_FILE, timeout=timeout)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    return conn


def _init_indexes(cur):
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_timestamp_id
        ON logs(timestamp DESC, id DESC)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_severity_timestamp_id
        ON logs(severity, timestamp DESC, id DESC)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_protocol_timestamp_id
        ON logs(protocol, timestamp DESC, id DESC)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_facility_timestamp_id
        ON logs(facility, timestamp DESC, id DESC)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_hostname_timestamp_id
        ON logs(hostname COLLATE NOCASE, timestamp DESC, id DESC)
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_source_ip_timestamp_id
        ON logs(source_ip COLLATE NOCASE, timestamp DESC, id DESC)
    """)


def _init_fts(cur):
    try:
        cur.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
                timestamp,
                source_ip,
                hostname,
                severity_text,
                message,
                protocol,
                content='logs',
                content_rowid='id'
            )
        """)
        cur.execute("""
            CREATE TRIGGER IF NOT EXISTS logs_ai AFTER INSERT ON logs BEGIN
                INSERT INTO logs_fts(rowid, timestamp, source_ip, hostname, severity_text, message, protocol)
                VALUES (new.id, new.timestamp, new.source_ip, new.hostname, new.severity_text, new.message, new.protocol);
            END
        """)
        cur.execute("""
            CREATE TRIGGER IF NOT EXISTS logs_ad AFTER DELETE ON logs BEGIN
                INSERT INTO logs_fts(logs_fts, rowid, timestamp, source_ip, hostname, severity_text, message, protocol)
                VALUES ('delete', old.id, old.timestamp, old.source_ip, old.hostname, old.severity_text, old.message, old.protocol);
            END
        """)
        cur.execute("""
            CREATE TRIGGER IF NOT EXISTS logs_au AFTER UPDATE ON logs BEGIN
                INSERT INTO logs_fts(logs_fts, rowid, timestamp, source_ip, hostname, severity_text, message, protocol)
                VALUES ('delete', old.id, old.timestamp, old.source_ip, old.hostname, old.severity_text, old.message, old.protocol);
                INSERT INTO logs_fts(rowid, timestamp, source_ip, hostname, severity_text, message, protocol)
                VALUES (new.id, new.timestamp, new.source_ip, new.hostname, new.severity_text, new.message, new.protocol);
            END
        """)
        has_rows = cur.execute("SELECT 1 FROM logs_fts LIMIT 1").fetchone()
        if has_rows is None:
            cur.execute("""
                INSERT INTO logs_fts(rowid, timestamp, source_ip, hostname, severity_text, message, protocol)
                SELECT id, timestamp, source_ip, hostname, severity_text, message, protocol
                FROM logs
            """)
        return True
    except sqlite3.OperationalError as exc:
        logging.info(f"[Syslog] FTS disabled for syslog DB: {exc}")
        return False


def _init_db():
    conn = _open_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                hostname TEXT,
                facility INTEGER,
                severity INTEGER,
                severity_text TEXT,
                message TEXT,
                protocol TEXT
            )
        """)
        _init_indexes(cur)
        _init_fts(cur)
        conn.commit()
    finally:
        conn.close()
    logging.info(f"[Syslog] Database initialized: {DB_FILE}")


def _insert_log(entry):
    try:
        conn = _open_db(timeout=5)
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO logs (timestamp, source_ip, hostname, facility, severity, severity_text, message, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, entry)
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logging.debug(f"[Syslog] Insert failed: {e}")


def parse_syslog(message):
    hostname = "unknown"
    facility = None
    severity = None
    severity_text = "unknown"
    msg = message

    try:
        if message.startswith("<"):
            pri_end = message.find(">")
            pri = int(message[1:pri_end])
            facility = pri // 8
            severity = pri % 8
            severity_text = SEVERITY_MAP.get(severity, "unknown")
            rest = message[pri_end + 1:].strip()
            parts = rest.split()
            if len(parts) >= 4:
                hostname = parts[3]
                msg = " ".join(parts[4:])
            else:
                msg = rest
    except Exception:
        pass

    return hostname, facility, severity, severity_text, msg


def _udp_listener(host, port):
    """UDP syslog listener using plain sockets (gevent-compatible)"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        logging.info(f"[Syslog] UDP listening on {host}:{port}")
    except OSError as e:
        logging.warning(f"[Syslog] UDP bind failed on {host}:{port}: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(8192)
            message = data.decode(errors="ignore").strip()
            if not message:
                continue
            hostname, facility, severity, severity_text, msg = parse_syslog(message)
            entry = (
                datetime.now().isoformat(),
                addr[0], hostname, facility, severity, severity_text, msg, "UDP"
            )
            _insert_log(entry)
        except Exception as e:
            logging.debug(f"[Syslog] UDP error: {e}")
            time.sleep(0.1)


def _tcp_listener(host, port):
    """TCP syslog listener using plain sockets (gevent-compatible)"""
    import socket
    import gevent
    from gevent import socket as gsocket

    srv = gsocket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
        srv.listen(32)
        logging.info(f"[Syslog] TCP listening on {host}:{port}")
    except OSError as e:
        logging.warning(f"[Syslog] TCP bind failed on {host}:{port}: {e}")
        return

    def handle_client(client_sock, addr):
        try:
            buf = b""
            while True:
                data = client_sock.recv(4096)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    message = line.decode(errors="ignore").strip()
                    if message:
                        hostname, facility, severity, severity_text, msg = parse_syslog(message)
                        entry = (
                            datetime.now().isoformat(),
                            addr[0], hostname, facility, severity, severity_text, msg, "TCP"
                        )
                        _insert_log(entry)
        except Exception:
            pass
        finally:
            client_sock.close()

    while True:
        try:
            client, addr = srv.accept()
            gevent.spawn(handle_client, client, addr)
        except Exception as e:
            logging.debug(f"[Syslog] TCP accept error: {e}")
            time.sleep(0.1)


def _syslog_loop():
    """Main syslog server loop — runs UDP + TCP in gevent greenlets"""
    import gevent

    _init_db()

    port = 1514
    host = "0.0.0.0"

    udp = gevent.spawn(_udp_listener, host, port)
    tcp = gevent.spawn(_tcp_listener, host, port)

    logging.info(f"[Syslog] Server started on port {port} (UDP+TCP)")
    gevent.joinall([udp, tcp])


def start_syslog_server():
    """Start syslog server in a background thread"""
    global _syslog_thread
    if _syslog_thread is not None:
        return

    _syslog_thread = threading.Thread(target=_syslog_loop, daemon=True, name='syslog-server')
    _syslog_thread.start()
    logging.info("[Syslog] Background thread started")
