# Server-side VNC framebuffer grab for the corporate "Console Available" tile.
# NS Jun 2026 — speaks just enough RFB 3.8 to pull ONE framebuffer off a running
# QEMU VM and hand back a PNG thumbnail. No SSH, no qemu-agent, no screendump
# command — purely the same vncproxy+websocket path the live console already uses
# (vms.py vnc_poll). shared-flag is set so grabbing a frame never kicks a user
# who has the console open.
#
# We force a known pixel format (32bpp little-endian BGRX) + Raw encoding so the
# decode is a straight PIL frombytes; we don't implement tile/hextile/zrle.

import io
import struct
import logging

# RFB message / security constants
_SEC_NONE = 1
_SEC_VNC = 2

_MSG_SET_PIXEL_FORMAT = 0
_MSG_SET_ENCODINGS = 2
_MSG_FB_UPDATE_REQUEST = 3

_SRV_FB_UPDATE = 0
_SRV_SET_COLORMAP = 1
_SRV_BELL = 2
_SRV_CUT_TEXT = 3

_ENC_RAW = 0

# safety cap: a 4096x4096x4 raw frame is 64MB; refuse anything sillier so a bogus
# ServerInit can't make us allocate the box to death.
_MAX_DIM = 4096
_MAX_RAW_BYTES = 64 * 1024 * 1024


def _reverse_bits(b):
    # VNC's DES variant mirrors the bit order of every key byte. Yes, really.
    return int('{:08b}'.format(b)[::-1], 2)


def _vnc_auth_response(password, challenge):
    """16-byte DES response to a 16-byte challenge, keyed by the (≤8 byte) password.

    cryptography dropped a standalone DES years ago, but TripleDES with the same
    8-byte key three times collapses to single-DES — which is exactly classic VNC
    auth. We already lean on this trick elsewhere in the VNC stack.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    # cryptography 48 moved TripleDES into the 'decrepit' namespace and dropped it
    # from primitives — prefer the new path, fall back for <48 installs.
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    key = bytearray(8)
    pw = password[:8]
    for i in range(len(pw)):
        key[i] = _reverse_bits(pw[i])
    des3_key = bytes(key) * 3
    enc = Cipher(TripleDES(des3_key), modes.ECB()).encryptor()
    return enc.update(challenge) + enc.finalize()


class _WsReader:
    """RFB is a byte stream; the PVE proxy chops it into arbitrary binary WS
    frames. Buffer them so we can read exact-length RFB fields."""
    def __init__(self, ws):
        self.ws = ws
        self.buf = b''

    def read(self, n):
        while len(self.buf) < n:
            chunk = self.ws.recv()
            if chunk is None or chunk == '':
                raise IOError('vnc websocket closed mid-stream')
            if isinstance(chunk, str):
                # binary frames come back as bytes; a str means a control/text
                # frame slipped through — treat its raw bytes as stream data
                chunk = chunk.encode('latin-1')
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


# 32bpp, depth 24, little-endian, true-colour, shifts R=16/G=8/B=0 → on the wire
# each pixel is bytes [B, G, R, X]. PIL's 'BGRX' raw decoder reads exactly that.
def _our_pixel_format():
    return struct.pack(
        '>BBBBHHHBBB3x',
        32,    # bits-per-pixel
        24,    # depth
        0,     # big-endian flag (0 = little)
        1,     # true-colour
        255, 255, 255,   # r/g/b max
        16, 8, 0,        # r/g/b shift
    )


def grab_frame(ws, vnc_ticket, timeout=8.0):
    """Run the RFB handshake on an already-connected PVE vncwebsocket and return
    a PIL.Image of the current framebuffer. `vnc_ticket` is the vncproxy ticket
    (used as the RFB password)."""
    from PIL import Image

    try:
        ws.settimeout(timeout)
    except Exception:
        pass

    r = _WsReader(ws)

    # 1) ProtocolVersion — server greets, we echo a version we can speak.
    server_ver = r.read(12)
    if not server_ver.startswith(b'RFB '):
        raise IOError('not an RFB stream: %r' % server_ver[:12])
    try:
        major = int(server_ver[4:7]); minor = int(server_ver[8:11])
    except Exception:
        major, minor = 3, 8
    ws.send(b'RFB 003.008\n')

    # 2) Security. 3.7+ → server lists types, we pick. 3.3 → server dictates one.
    if (major, minor) >= (3, 7):
        n_types = r.read(1)[0]
        if n_types == 0:
            reason_len = struct.unpack('>I', r.read(4))[0]
            raise IOError('vnc security failed: %s' % r.read(reason_len).decode('latin-1', 'replace'))
        types = set(r.read(n_types))
        chosen = _SEC_VNC if _SEC_VNC in types else (_SEC_NONE if _SEC_NONE in types else None)
        if chosen is None:
            raise IOError('no supported vnc security type offered: %r' % sorted(types))
        ws.send(bytes([chosen]))
    else:
        chosen = struct.unpack('>I', r.read(4))[0]

    # 3) VNC auth (challenge/response) when required.
    if chosen == _SEC_VNC:
        challenge = r.read(16)
        ws.send(_vnc_auth_response(vnc_ticket.encode('latin-1', 'replace'), challenge))
        sec_result = struct.unpack('>I', r.read(4))[0]
        if sec_result != 0:
            # 3.8 appends a reason; older versions just drop.
            try:
                rl = struct.unpack('>I', r.read(4))[0]
                why = r.read(rl).decode('latin-1', 'replace')
            except Exception:
                why = 'auth rejected'
            raise IOError('vnc auth failed: %s' % why)

    # 4) ClientInit — shared=1 so we don't boot an existing console session.
    ws.send(b'\x01')

    # 5) ServerInit: width, height, pixel-format(16), name.
    head = r.read(4)
    fb_w, fb_h = struct.unpack('>HH', head)
    r.read(16)  # server's native pixel format — we override it below
    name_len = struct.unpack('>I', r.read(4))[0]
    if name_len:
        r.read(name_len)
    if fb_w <= 0 or fb_h <= 0 or fb_w > _MAX_DIM or fb_h > _MAX_DIM:
        raise IOError('implausible framebuffer size %dx%d' % (fb_w, fb_h))

    # 6) Pin our pixel format + Raw-only, then ask for the whole screen (non-incremental).
    ws.send(struct.pack('>Bxxx', _MSG_SET_PIXEL_FORMAT) + _our_pixel_format())
    ws.send(struct.pack('>BxH', _MSG_SET_ENCODINGS, 1) + struct.pack('>i', _ENC_RAW))
    ws.send(struct.pack('>BBHHHH', _MSG_FB_UPDATE_REQUEST, 0, 0, 0, fb_w, fb_h))

    # 7) Read messages until we get a FramebufferUpdate; skip bell/colormap/cut-text.
    img = Image.new('RGB', (fb_w, fb_h), (0, 0, 0))
    deadline_guard = 0
    while True:
        deadline_guard += 1
        if deadline_guard > 64:
            raise IOError('no framebuffer update after 64 server messages')
        msg_type = r.read(1)[0]
        if msg_type == _SRV_FB_UPDATE:
            r.read(1)  # padding
            n_rects = struct.unpack('>H', r.read(2))[0]
            for _ in range(n_rects):
                x, y, w, h, enc = struct.unpack('>HHHHi', r.read(12))
                if enc != _ENC_RAW:
                    raise IOError('server used unexpected encoding %d' % enc)
                nbytes = w * h * 4
                if nbytes > _MAX_RAW_BYTES:
                    raise IOError('raw rect too large (%d bytes)' % nbytes)
                if nbytes == 0:
                    continue
                data = r.read(nbytes)
                rect = Image.frombytes('RGB', (w, h), data, 'raw', 'BGRX')
                img.paste(rect, (x, y))
            return img
        elif msg_type == _SRV_SET_COLORMAP:
            r.read(3)  # padding + first-colour
            ncolors = struct.unpack('>H', r.read(2))[0]
            r.read(ncolors * 6)
        elif msg_type == _SRV_BELL:
            pass
        elif msg_type == _SRV_CUT_TEXT:
            r.read(3)  # padding
            tlen = struct.unpack('>I', r.read(4))[0]
            r.read(tlen)
        else:
            raise IOError('unexpected server message type %d' % msg_type)


def to_png_thumbnail(img, max_width=480):
    """Downscale to a tile-sized PNG. Keeps aspect ratio."""
    from PIL import Image
    if img.width > max_width:
        ratio = max_width / float(img.width)
        img = img.resize((max_width, max(1, int(img.height * ratio))), Image.BILINEAR)
    out = io.BytesIO()
    img.save(out, format='PNG', optimize=True)
    return out.getvalue()
