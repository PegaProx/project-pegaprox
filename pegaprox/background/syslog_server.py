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

# DB in config dir, not CWD
DB_FILE = os.path.join(CONFIG_DIR, 'syslog.db')

SEVERITY_MAP = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug"
}

_syslog_thread = None


def _connect_db(timeout=5):
    conn = sqlite3.connect(DB_FILE, timeout=timeout)
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute(f"PRAGMA busy_timeout={int(timeout * 1000)};")
    return conn


def _init_db():
    conn = _connect_db()
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            timestamp_unix INTEGER NOT NULL,
            source_ip TEXT,
            hostname TEXT,
            facility INTEGER,
            severity INTEGER,
            severity_text TEXT,
            message TEXT,
            protocol TEXT
        )
    """)
    columns = {row[1] for row in cur.execute("PRAGMA table_info(logs)").fetchall()}
    if 'timestamp_unix' not in columns:
        cur.execute("ALTER TABLE logs ADD COLUMN timestamp_unix INTEGER")
        cur.execute("""
            UPDATE logs
            SET timestamp_unix = COALESCE(
                timestamp_unix,
                CAST(unixepoch(timestamp) AS INTEGER),
                CAST(unixepoch(REPLACE(timestamp, 'T', ' ')) AS INTEGER),
                0
            )
            WHERE timestamp_unix IS NULL
        """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp_unix_id ON logs(timestamp_unix DESC, id DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity_timestamp ON logs(severity, timestamp_unix DESC, id DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_facility_timestamp ON logs(facility, timestamp_unix DESC, id DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_protocol_timestamp ON logs(protocol, timestamp_unix DESC, id DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_hostname_timestamp ON logs(hostname, timestamp_unix DESC, id DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_source_ip_timestamp ON logs(source_ip, timestamp_unix DESC, id DESC)")
    conn.commit()
    conn.close()
    logging.info(f"[Syslog] Database initialized: {DB_FILE}")


def _insert_log(entry):
    try:
        conn = _connect_db(timeout=5)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO logs (timestamp, timestamp_unix, source_ip, hostname, facility, severity, severity_text, message, protocol)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, entry)
        conn.commit()
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
                int(time.time()),
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
                            int(time.time()),
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

    _init_db()
    _syslog_thread = threading.Thread(target=_syslog_loop, daemon=True, name='syslog-server')
    _syslog_thread.start()
    logging.info("[Syslog] Background thread started")
