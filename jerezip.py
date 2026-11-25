#!/usr/bin/env python3
"""
JereZip - heavy-compression archiver  (.jlzip = Jeremy Leon Zipping)

How it squeezes harder than ZIP:
  * SOLID archive: every file goes into ONE LZMA2 stream, so redundancy
    BETWEEN files is exploited (ZIP compresses each file separately).
  * Similar files are grouped together (sorted by extension) first.
  * Huge dictionary (up to 256 MB) and extreme match-finder settings.
  * BCJ filters: x86 / ARM / ARM64 machine code (.exe, .dll, .so ...) is
    transformed so jump/call addresses compress much better. "auto" sniffs the
    files (PE / ELF headers) and enables the right filter when it pays off.
  * SHA-256 integrity check over the whole stream.

Password protection (optional, needs:  pip install cryptography):
  * AES-256-GCM, key derived with scrypt (memory-hard, slows brute force).
  * File NAMES are encrypted too (the index lives inside the encrypted stream).
  * Wrong password / tampering / truncation is detected.

Usage:
  python jerezip.py                         -> opens the GUI
  python jerezip.py c out.jlzip a b c/      -> compress
        -l normal|max|ultra   compression level (default max)
        -f auto|none|x86|arm|arm64   BCJ filter (default auto)
        -p                    ask for a password (prompted, never on the command line)
  python jerezip.py x out.jlzip [destdir]   -> extract (asks for password if needed)
  python jerezip.py l out.jlzip             -> list contents

File layout:
  b"JLZP" | version(1) | flags(1) | [if encrypted: log2(scrypt N)(1) | salt(16)]
  then an XZ stream (LZMA2, SHA-256 check) containing
  [4-byte index length][JSON index][raw file bytes concatenated].
  If encrypted, that XZ stream is cut into 1 MB chunks, each AES-GCM sealed.
"""
import getpass
import hashlib
import json
import lzma
import os
import struct
import sys
import threading

MAGIC = b"JLZP"
VERSION = 1
FLAG_ENC = 1
EXT = ".jlzip"
CHUNK = 1 << 20
MB = 1 << 20
SCRYPT_LOGN = 15  # N=32768, r=8 -> ~32 MB, a good desktop-grade cost

LEVELS = {
    "normal": (16 * MB, "~100-200 MB RAM"),
    "max": (64 * MB, "~800 MB RAM"),
    "ultra": (256 * MB, "~3 GB RAM to compress"),
}
FILTER_CHOICES = ["auto", "none", "x86", "arm", "arm64"]


class PasswordRequired(Exception):
    pass


# ----------------------------------------------------------------- crypto
def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError:
        raise RuntimeError("Passwords need the 'cryptography' package:  pip install cryptography")


def _derive(password, salt, logn):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=1 << logn, r=8, p=1,
                          maxmem=256 * MB, dklen=32)


class _EncWriter:
    """File-like sink: seals everything written into AES-GCM chunks."""

    def __init__(self, fp, key, aad):
        self.fp, self.aes, self.aad = fp, _aesgcm()(key), aad
        self.buf, self.n = bytearray(), 0

    def write(self, data):
        self.buf += data
        while len(self.buf) > CHUNK:  # always keep >=1 byte back for the final chunk
            self._emit(bytes(self.buf[:CHUNK]), False)
            del self.buf[:CHUNK]
        return len(data)

    def flush(self):
        pass

    def _emit(self, chunk, final):
        nonce = struct.pack("<QI", self.n, 0)
        self.n += 1
        ct = self.aes.encrypt(nonce, chunk, self.aad + (b"\x01" if final else b"\x00"))
        self.fp.write(struct.pack("<I", len(ct)))
        self.fp.write(ct)

    def finish(self):
        self._emit(bytes(self.buf), True)  # "final" flag defeats truncation attacks
        self.buf.clear()


class _DecReader:
    """File-like source: opens AES-GCM chunks produced by _EncWriter."""

    def __init__(self, fp, key, aad):
        from cryptography.exceptions import InvalidTag
        self._bad = InvalidTag
        self.fp, self.aes, self.aad = fp, _aesgcm()(key), aad
        self.buf, self.pos, self.n = b"", 0, 0
        self.pending = self._record()

    def readable(self):
        return True

    def _record(self):
        h = self.fp.read(4)
        if not h:
            return None
        if len(h) < 4:
            raise ValueError("Archive is truncated")
        (length,) = struct.unpack("<I", h)
        ct = self.fp.read(length)
        if len(ct) < length:
            raise ValueError("Archive is truncated")
        return ct

    def _fill(self):
        if self.pending is None:
            return False
        cur, self.pending = self.pending, self._record()
        final = self.pending is None
        nonce = struct.pack("<QI", self.n, 0)
        self.n += 1
        try:
            pt = self.aes.decrypt(nonce, cur, self.aad + (b"\x01" if final else b"\x00"))
        except self._bad:
            raise ValueError("Wrong password, or the archive is corrupt / truncated")
        self.buf = self.buf[self.pos:] + pt
        self.pos = 0
        return True

    def read(self, size=-1):
        if size is None or size < 0:
            while self._fill():
                pass
            size = len(self.buf) - self.pos
        while len(self.buf) - self.pos < size and self._fill():
            pass
        out = self.buf[self.pos:self.pos + size]
        self.pos += len(out)
        return out


# ----------------------------------------------------------------- filters
def sniff_arch(path):
    """Best guess at the CPU arch of an executable, or None."""
    try:
        with open(path, "rb") as f:
            h = f.read(4096)
    except OSError:
        return None
    if h[:4] == b"\x7fELF" and len(h) > 19:
        return {0x3E: "x86", 0x03: "x86", 0xB7: "arm64", 0x28: "arm"}.get(
            int.from_bytes(h[18:20], "little"))
    if h[:2] == b"MZ" and len(h) > 0x40:
        off = int.from_bytes(h[0x3C:0x40], "little")
        if off + 6 <= len(h) and h[off:off + 4] == b"PE\0\0":
            return {0x14C: "x86", 0x8664: "x86", 0xAA64: "arm64", 0x1C0: "arm", 0x1C4: "arm"}.get(
                int.from_bytes(h[off + 4:off + 6], "little"))
    return None


def _bcj_id(name):
    ids = {"x86": getattr(lzma, "FILTER_X86", None), "arm": getattr(lzma, "FILTER_ARM", None),
           "arm64": getattr(lzma, "FILTER_ARM64", None)}
    return ids.get(name)


def choose_filter(choice, entries):
    """Returns the BCJ name to use ('x86','arm','arm64') or None."""
    if choice == "none":
        return None
    if choice != "auto":
        if _bcj_id(choice) is None:
            raise RuntimeError(f"Your Python/liblzma has no {choice} filter (needs Python 3.12+ for arm64)")
        return choice
    weight, total = {}, 0
    for full, arc, is_dir in entries:
        if is_dir:
            continue
        size = os.path.getsize(full)
        total += size
        arch = sniff_arch(full)
        if arch and _bcj_id(arch) is not None:
            weight[arch] = weight.get(arch, 0) + size
    if not weight or not total:
        return None
    best = max(weight, key=weight.get)
    return best if weight[best] >= 0.4 * total else None  # only if it pays off


def _filters(level, total_size, bcj):
    d = 1 * MB
    while d < total_size and d < LEVELS[level][0]:  # no point in a dict bigger than the data
        d <<= 1
    chain = []
    if bcj:
        chain.append({"id": _bcj_id(bcj)})
    chain.append({
        "id": lzma.FILTER_LZMA2,
        "preset": 9 | lzma.PRESET_EXTREME,
        "dict_size": min(d, LEVELS[level][0]),
        "nice_len": 273,
        "mf": lzma.MF_BT4,
        "depth": 1000 if level != "normal" else 0,
    })
    return chain


# ----------------------------------------------------------------- archive
def collect(paths):
    out = []
    for p in paths:
        p = os.path.abspath(p)
        base = os.path.dirname(p)
        if os.path.isdir(p):
            out.append((p, os.path.relpath(p, base).replace(os.sep, "/"), True))
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for d in dirs:
                    full = os.path.join(root, d)
                    out.append((full, os.path.relpath(full, base).replace(os.sep, "/"), True))
                for f in files:
                    full = os.path.join(root, f)
                    out.append((full, os.path.relpath(full, base).replace(os.sep, "/"), False))
        elif os.path.isfile(p):
            out.append((p, os.path.basename(p), False))
    dirs = [e for e in out if e[2]]
    files = [e for e in out if not e[2]]
    files.sort(key=lambda e: (os.path.splitext(e[1])[1].lower(), e[1].lower()))
    return dirs + files


def compress(out_path, paths, level="max", progress=None, password=None, bcj="auto"):
    """Returns (original_size, archive_size, bcj_filter_used_or_None)."""
    entries = collect(paths)
    index, total = [], 0
    for full, arc, is_dir in entries:
        if is_dir:
            index.append({"p": arc, "d": 1})
        else:
            st = os.stat(full)
            index.append({"p": arc, "s": st.st_size, "m": int(st.st_mtime)})
            total += st.st_size
    idx = json.dumps(index, separators=(",", ":")).encode("utf-8")
    used = choose_filter(bcj, entries)
    filters = _filters(level, total, used)

    head = MAGIC + bytes([VERSION, FLAG_ENC if password else 0])
    sink_enc = None
    done = 0
    with open(out_path, "wb") as raw:
        if password:
            salt = os.urandom(16)
            extra = bytes([SCRYPT_LOGN]) + salt
            raw.write(head + extra)
            sink_enc = _EncWriter(raw, _derive(password, salt, SCRYPT_LOGN), head + extra)
            sink = sink_enc
        else:
            raw.write(head)
            sink = raw
        with lzma.LZMAFile(sink, "wb", format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256,
                           filters=filters) as xz:
            xz.write(struct.pack("<I", len(idx)))
            xz.write(idx)
            for (full, arc, is_dir), meta in zip(entries, index):
                if is_dir:
                    continue
                remaining = meta["s"]
                with open(full, "rb") as f:
                    while remaining > 0:
                        b = f.read(min(CHUNK, remaining))
                        if not b:
                            raise IOError(f"{full} shrank while compressing")
                        xz.write(b)
                        remaining -= len(b)
                        done += len(b)
                        if progress:
                            progress(done, total, arc)
        if sink_enc:
            sink_enc.finish()
    return total, os.path.getsize(out_path), used


def is_encrypted(path):
    with open(path, "rb") as f:
        head = f.read(6)
    if head[:4] != MAGIC:
        raise ValueError("Not a JereZip (.jlzip) file")
    return bool(head[5] & FLAG_ENC)


def _open(path, password):
    raw = open(path, "rb")
    try:
        head = raw.read(6)
        if head[:4] != MAGIC:
            raise ValueError("Not a JereZip (.jlzip) file")
        if head[4] != VERSION:
            raise ValueError("Archive was made by a newer JereZip version")
        src = raw
        if head[5] & FLAG_ENC:
            if not password:
                raise PasswordRequired("This archive is password protected")
            extra = raw.read(17)
            src = _DecReader(raw, _derive(password, extra[1:], extra[0]), head + extra)
        xz = lzma.LZMAFile(src, "rb")
        try:
            (n,) = struct.unpack("<I", xz.read(4))
            index = json.loads(xz.read(n).decode("utf-8"))
        except (lzma.LZMAError, struct.error, UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Archive is corrupt")
        return raw, xz, index
    except BaseException:
        raw.close()
        raise


def list_archive(path, password=None):
    raw, xz, index = _open(path, password)
    xz.close()
    raw.close()
    return index


def extract(path, dest, progress=None, password=None):
    dest = os.path.abspath(dest)
    raw, xz, index = _open(path, password)
    total = sum(e.get("s", 0) for e in index)
    done = 0
    try:
        for e in index:
            target = os.path.abspath(os.path.join(dest, e["p"]))
            if os.path.commonpath([dest, target]) != dest:  # block ../ path tricks
                raise ValueError(f"Unsafe path in archive: {e['p']}")
            if e.get("d"):
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            remaining = e["s"]
            with open(target, "wb") as f:
                while remaining > 0:
                    b = xz.read(min(CHUNK, remaining))
                    if not b:
                        raise EOFError("Archive is truncated or corrupt")
                    f.write(b)
                    remaining -= len(b)
                    done += len(b)
                    if progress:
                        progress(done, total, e["p"])
            os.utime(target, (e["m"], e["m"]))
        xz.read(1)  # forces the final SHA-256 check
    finally:
        xz.close()
        raw.close()
    return total


def fmt(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.1f} {u}" if u != "B" else f"{n} B"
        n /= 1024


# ----------------------------------------------------------------- GUI
def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, simpledialog

    root = tk.Tk()
    root.title("JereZip")
    root.geometry("700x480")
    items = []

    top = ttk.Frame(root, padding=(8, 8, 8, 2))
    top.pack(fill="x")
    opts = ttk.Frame(root, padding=(8, 2, 8, 6))
    opts.pack(fill="x")
    box = tk.Listbox(root, selectmode="extended")
    box.pack(fill="both", expand=True, padx=8)
    bar = ttk.Progressbar(root, maximum=100)
    bar.pack(fill="x", padx=8, pady=(8, 2))
    status = ttk.Label(root, text="Add files or folders, pick options, then Compress.")
    status.pack(fill="x", padx=8, pady=(0, 8))

    def ui(fn):
        root.after(0, fn)

    def prog(done, total, name):
        pct = 100 * done / total if total else 100
        ui(lambda: (bar.configure(value=pct), status.configure(text=f"{pct:.0f}%  {name}")))

    def add_files():
        for p in filedialog.askopenfilenames():
            items.append(p); box.insert("end", p)

    def add_folder():
        p = filedialog.askdirectory()
        if p:
            items.append(p); box.insert("end", p)

    def clear():
        items.clear(); box.delete(0, "end")

    def worker(fn):
        def run():
            try:
                msg = fn()
                ui(lambda: (status.configure(text=msg), messagebox.showinfo("JereZip", msg)))
            except Exception as ex:
                err = str(ex)
                ui(lambda: (status.configure(text="Error"), messagebox.showerror("JereZip", err)))
        threading.Thread(target=run, daemon=True).start()

    def get_password_for(src):
        """Password for opening an archive (None if it isn't encrypted)."""
        if not is_encrypted(src):
            return None
        return pw.get() or simpledialog.askstring("JereZip", "Archive password:", show="*")

    def do_compress():
        if not items:
            return messagebox.showwarning("JereZip", "Add something first.")
        password = pw.get() or None
        if password and simpledialog.askstring("JereZip", "Type the password again:", show="*") != password:
            return messagebox.showerror("JereZip", "Passwords don't match.")
        out = filedialog.asksaveasfilename(defaultextension=EXT, filetypes=[("JereZip", "*" + EXT)])
        if not out:
            return
        lvl, flt = level.get(), bcj.get()

        def job():
            a, b, used = compress(out, list(items), lvl, prog, password, flt)
            extra = f"  [BCJ {used}]" if used else ""
            lock = "  [encrypted]" if password else ""
            return f"Done: {fmt(a)} -> {fmt(b)}  ({100 * b / max(a, 1):.1f}%){extra}{lock}"
        worker(job)

    def do_extract():
        src = filedialog.askopenfilename(filetypes=[("JereZip", "*" + EXT)])
        if not src:
            return
        try:
            password = get_password_for(src)
        except Exception as ex:
            return messagebox.showerror("JereZip", str(ex))
        dest = filedialog.askdirectory(title="Extract to...")
        if not dest:
            return

        def job():
            n = extract(src, dest, prog, password)
            return f"Extracted {fmt(n)} (integrity verified)"
        worker(job)

    def do_list():
        src = filedialog.askopenfilename(filetypes=[("JereZip", "*" + EXT)])
        if not src:
            return
        try:
            idx = list_archive(src, get_password_for(src))
        except Exception as ex:
            return messagebox.showerror("JereZip", str(ex))
        box.delete(0, "end")
        for e in idx:
            box.insert("end", ("[dir]  " if e.get("d") else f"{fmt(e['s']):>10}  ") + e["p"])
        status.configure(text=f"{len(idx)} entries (list view - press Clear before compressing)")

    for text, cmd in (("Add files", add_files), ("Add folder", add_folder), ("Clear", clear),
                      ("Compress", do_compress), ("Extract", do_extract), ("List", do_list)):
        ttk.Button(top, text=text, command=cmd).pack(side="left", padx=2)

    level, bcj, pw = tk.StringVar(value="max"), tk.StringVar(value="auto"), tk.StringVar()
    ttk.Label(opts, text="Level").pack(side="left")
    ttk.Combobox(opts, textvariable=level, values=list(LEVELS), state="readonly", width=7).pack(side="left", padx=(4, 12))
    ttk.Label(opts, text="BCJ filter").pack(side="left")
    ttk.Combobox(opts, textvariable=bcj, values=FILTER_CHOICES, state="readonly", width=7).pack(side="left", padx=(4, 12))
    ttk.Label(opts, text="Password").pack(side="left")
    ttk.Entry(opts, textvariable=pw, show="*", width=22).pack(side="left", padx=4)
    root.mainloop()


# ----------------------------------------------------------------- CLI
def main(argv):
    if len(argv) < 2:
        return run_gui()

    def cli_prog(done, total, name):
        pct = 100 * done / total if total else 100
        print(f"\r{pct:5.1f}%  {name[-60:]:<60}", end="", flush=True)

    def ask_pw(confirm=False):
        p = getpass.getpass("Password: ")
        if confirm and getpass.getpass("Again: ") != p:
            sys.exit("Passwords don't match")
        return p

    cmd, args = argv[1], argv[2:]
    try:
        if cmd == "c" and len(args) >= 2:
            level, flt, password = "max", "auto", None
            if "-l" in args:
                i = args.index("-l"); level = args[i + 1]; del args[i:i + 2]
            if "-f" in args:
                i = args.index("-f"); flt = args[i + 1]; del args[i:i + 2]
            if "-p" in args:
                args.remove("-p"); password = ask_pw(confirm=True)
            a, b, used = compress(args[0], args[1:], level, cli_prog, password, flt)
            print(f"\n{fmt(a)} -> {fmt(b)} ({100 * b / max(a, 1):.1f}%)"
                  + (f"  BCJ={used}" if used else "") + ("  encrypted" if password else ""))
        elif cmd in ("x", "l") and args:
            pw = ask_pw() if is_encrypted(args[0]) else None
            if cmd == "x":
                extract(args[0], args[1] if len(args) > 1 else ".", cli_prog, pw)
                print("\nOK, integrity verified")
            else:
                for e in list_archive(args[0], pw):
                    print(("[dir] " if e.get("d") else f"{e['s']:>12} ") + e["p"])
        else:
            print(__doc__)
    except (ValueError, RuntimeError, EOFError, lzma.LZMAError) as ex:
        sys.exit(f"\nError: {ex}")


if __name__ == "__main__":
    main(sys.argv)
