#!/usr/bin/env python3
import asyncio, os, re
from Crypto.Cipher import AES

BLOCK = 16
IDLE_TIMEOUT = int(os.environ.get("IDLE_TIMEOUT", "60"))  # seconds
MAX_LINE_LEN = 4096
MAX_MSG_LEN  = 4096       # for oracle queries (bytes, pre-padding)
MAX_CODE_LEN = 8192       # submission upper bound (bytes)

FLAG   = os.environ.get("FLAG", "Flag{1ts_just_34sy_crypt0_w0rk}").encode()
KEY    = os.urandom(16)   # keep secret; oracle & verifier share this process
POLICY = b"print('Attack detected')"

# ========== CBC-MAC (AES, IV=0, PKCS#7) ==========
def pkcs7(data: bytes, n: int = BLOCK) -> bytes:
    pad = (-len(data)) % n
    if pad == 0: pad = n
    return data + bytes([pad])*pad

def xorb(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def ecb_enc(key: bytes, block: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(block)

def cbc_enc_last_block(key: bytes, iv: bytes, msg: bytes) -> bytes:
    data = pkcs7(msg, BLOCK)
    prev = iv
    for i in range(0, len(data), BLOCK):
        prev = ecb_enc(key, xorb(data[i:i+BLOCK], prev))
    return prev  # last block

def cbc_mac(key: bytes, msg: bytes) -> bytes:
    return cbc_enc_last_block(key, b"\x00"*BLOCK, msg)

DESIRED_TAG = cbc_mac(KEY, POLICY)

# ========== Regex: print("Nothing to see here") then '#' ==========
WORD_SP   = r"\s+"
MSG_WORDS = r"Nothing" + WORD_SP + r"to" + WORD_SP + r"see" + WORD_SP + r"here"
PRINT_RE  = re.compile(
    r'^\s*print\s*\(\s*(["\'])' + MSG_WORDS + r'\1\s*\)\s*#',
    re.DOTALL
)

def ascii_prefix_ok(code: bytes) -> bool:
    """
    Enforce printable ASCII only up to (and including) the first '#'.
    After '#', raw binary is allowed to let players append forged blocks.
    """
    try:
        idx = code.index(b'#')
    except ValueError:
        # if no '#', fail early (regex will also fail)
        return False
    prefix = code[:idx+1]  # include '#'
    return all(32 <= b < 127 or b in (9,10,13) for b in prefix)

def matches_regex(code: bytes) -> bool:
    # Decode ignoring non-ASCII that may appear after '#'
    s = code.decode("ascii", "ignore")
    return PRINT_RE.search(s) is not None

# ========== Async helpers ==========
async def send_line(w, s: str):
    w.write(s.encode() + b"\n")
    await w.drain()

async def read_line(r) -> str:
    try:
        data = await asyncio.wait_for(r.readline(), timeout=IDLE_TIMEOUT)
    except asyncio.TimeoutError:
        return ""  # timeout -> caller closes connection
    if not data:
        return ""
    if len(data) > MAX_LINE_LEN:
        return ""
    return data.rstrip(b"\r\n").decode(errors="ignore")

# ========== Oracle flow ==========
async def handle_oracle(reader, writer):
    await send_line(writer, "== CBC-MAC Oracle ==")
    await send_line(writer, f"Send msg_hex per line (max {MAX_MSG_LEN} bytes). Type 'back' to menu.")
    while True:
        line = await read_line(reader)
        if not line:
            return
        line = line.strip()
        if line.lower() in ("back", "quit", "exit"):
            return
        try:
            msg = bytes.fromhex(line)
        except Exception:
            await send_line(writer, "ERR: bad hex"); continue
        if len(msg) > MAX_MSG_LEN:
            await send_line(writer, "ERR: msg too long"); continue
        tag = cbc_mac(KEY, msg)
        await send_line(writer, tag.hex())

# ========== Submit flow ==========
async def handle_submit(reader, writer):
    await send_line(writer, "== Submit Code ==")
    await send_line(writer, "Rules:")
    await send_line(writer, '  - Must match regex: print("Nothing to see here") then "#" (spaces flexible, quotes \' or ")')
    await send_line(writer, "  - ASCII printable required only up to the first '#'; binary allowed after")
    await send_line(writer, f"  - CBC_MAC(code) must equal desired_tag: {DESIRED_TAG.hex()}")
    await send_line(writer, f"  - policy (utf-8): {POLICY.decode('utf-8','ignore')}")
    await send_line(writer, "Send code_hex on one line:")
    code_hex = await read_line(reader)
    if not code_hex:
        return
    code_hex = code_hex.strip()
    # rough bound
    if len(code_hex) > 2 * MAX_CODE_LEN:
        await send_line(writer, "ERR: code too long"); return
    try:
        code = bytes.fromhex(code_hex)
    except Exception:
        await send_line(writer, "ERR: invalid hex"); return

    if not ascii_prefix_ok(code):
        await send_line(writer, "ERR: non-ASCII before '#'/no '#'."); return
    if not matches_regex(code):
        await send_line(writer, 'ERR: regex mismatch (need print("Nothing to see here") then #, spaces allowed)')
        return

    if cbc_mac(KEY, code) != DESIRED_TAG:
        await send_line(writer, "ERR: tag mismatch (CBC_MAC(code) != desired_tag)"); return

    await send_line(writer, f"OK! {FLAG.decode('ascii','ignore')}")

# ========== Main handler with menu ==========
MENU = [
    "== CBC-MAC Challenge ==",
    "1) cbc_mac oracle",
    "2) submit code",
    "3) quit",
    f"(Idle timeout: {IDLE_TIMEOUT}s)"
]

async def handle_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        for line in MENU:
            await send_line(writer, line)
        while True:
            await send_line(writer, "Choice [1-3]:")
            choice = await read_line(reader)
            if not choice:
                break
            c = choice.strip()
            if c == "1":
                await handle_oracle(reader, writer)
            elif c == "2":
                await handle_submit(reader, writer)
            elif c == "3":
                break
            else:
                await send_line(writer, "ERR: invalid choice")
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

async def main():
    server = await asyncio.start_server(handle_conn, host="0.0.0.0", port=1337)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"[+] Listening on {addrs}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
