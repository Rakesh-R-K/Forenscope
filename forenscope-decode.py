#!/usr/bin/env python3
"""
forenscope-decode.py
Reads a file using forenscope.analyze(), finds b64/hex candidates and long printable strings,
attempts to decode them, writes decoded artifacts to artifacts/<basename>/ and produces a manifest.
"""
import os, sys, json, re, base64, binascii
from pathlib import Path
from hashlib import sha256
from math import log2
from forenscope import analyze, detect_magic  # uses your existing script's functions

# heuristics
MIN_CAND_LENGTH = 40   # minimum chars to attempt decode
STRINGS_SCAN_LIMIT = 2000  # how many extracted strings to scan
ARTIFACTS_DIR = Path.cwd() / "artifacts"

# reuse regex from forenscope
B64_RE = re.compile(r'^[A-Za-z0-9+/=\s]{40,}$')
HEX_RE = re.compile(r'^[0-9a-fA-F\s]{40,}$')

def entropy_bytes(data: bytes):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    l = len(data)
    for v in freq.values():
        p = v / l
        ent -= p * (log2(p) if p>0 else 0)
    return ent

def try_decode_b64(s):
    try:
        cleaned = re.sub(r'\s+', '', s)
        b = base64.b64decode(cleaned, validate=True)
        return b
    except Exception:
        return None

def try_decode_hex(s):
    try:
        cleaned = re.sub(r'\s+', '', s)
        # if odd length, try prefixing a '0'
        if len(cleaned) % 2 == 1:
            cleaned = '0' + cleaned
        b = binascii.unhexlify(cleaned)
        return b
    except Exception:
        return None

def safe_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)

def artifact_name(base_dir: Path, prefix: str, idx: int, ext: str = ".bin"):
    return base_dir / f"{prefix}_{idx}{ext}"

def scan_and_decode(report, target_path: Path):
    base = Path(target_path).stem
    outdir = ARTIFACTS_DIR / base
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = []
    idx = 0

    # 1) decode candidates reported by forenscope (b64_candidates / hex_candidates)
    for kind in ('b64_candidates','hex_candidates'):
        for i, item in enumerate(report.get(kind, [])):
            # for b64_candidates/hex_candidates we only have lengths in default ForenScope.
            # attempt to locate matching long strings in sample_strings to decode
            for s in report.get('sample_strings', [])[:STRINGS_SCAN_LIMIT]:
                if len(s) < MIN_CAND_LENGTH:
                    continue
                if kind == 'b64_candidates' and B64_RE.match(s):
                    data = try_decode_b64(s)
                    if data:
                        idx += 1
                        fname = artifact_name(outdir, 'b64', idx)
                        safe_write(fname, data)
                        manifest.append({
                            'source':'reported_b64',
                            'string_snippet': s[:100],
                            'outfile': str(fname),
                            'sha256': sha256(data).hexdigest(),
                            'size': len(data),
                            'entropy': entropy_bytes(data),
                            'detected_magic': detect_magic(str(fname)) if os.path.exists(str(fname)) else None
                        })
                if kind == 'hex_candidates' and HEX_RE.match(s):
                    data = try_decode_hex(s)
                    if data:
                        idx += 1
                        fname = artifact_name(outdir, 'hex', idx)
                        safe_write(fname, data)
                        manifest.append({
                            'source':'reported_hex',
                            'string_snippet': s[:100],
                            'outfile': str(fname),
                            'sha256': sha256(data).hexdigest(),
                            'size': len(data),
                            'entropy': entropy_bytes(data),
                            'detected_magic': detect_magic(str(fname)) if os.path.exists(str(fname)) else None
                        })

    # 2) scan the top printable strings for large base64/hex blobs (backup detection)
    scanned = 0
    for s in report.get('sample_strings', [])[:STRINGS_SCAN_LIMIT]:
        if len(s) < MIN_CAND_LENGTH:
            continue
        scanned += 1
        # try base64
        if B64_RE.match(s):
            data = try_decode_b64(s)
            if data:
                idx += 1
                fname = artifact_name(outdir, 'b64scan', idx)
                safe_write(fname, data)
                manifest.append({
                    'source':'scanned_b64',
                    'string_snippet': s[:100],
                    'outfile': str(fname),
                    'sha256': sha256(data).hexdigest(),
                    'size': len(data),
                    'entropy': entropy_bytes(data),
                    'detected_magic': detect_magic(str(fname)) if os.path.exists(str(fname)) else None
                })
                continue
        # try hex
        if HEX_RE.match(s):
            data = try_decode_hex(s)
            if data:
                idx += 1
                fname = artifact_name(outdir, 'hexscan', idx)
                safe_write(fname, data)
                manifest.append({
                    'source':'scanned_hex',
                    'string_snippet': s[:100],
                    'outfile': str(fname),
                    'sha256': sha256(data).hexdigest(),
                    'size': len(data),
                    'entropy': entropy_bytes(data),
                    'detected_magic': detect_magic(str(fname)) if os.path.exists(str(fname)) else None
                })

    # 3) also attempt to detect long base64-looking regions in the entire file (stream scan)
    # (optional) — we will scan the file bytes for long base64 runs
    try:
        raw = Path(target_path).read_bytes()
        # find long base64-like substrings in raw bytes (decoded as latin1)
        raw_text = raw.decode('latin1')
        for m in re.finditer(r'([A-Za-z0-9+/=\\s]{80,})', raw_text):
            s = m.group(1)
            # filter out ones with many '=' or whitespace ok
            if len(s) < 80:
                continue
            if B64_RE.match(s):
                data = try_decode_b64(s)
                if data:
                    idx += 1
                    fname = artifact_name(outdir, 'b64raw', idx)
                    safe_write(fname, data)
                    manifest.append({
                        'source':'raw_b64',
                        'string_snippet': s[:100],
                        'outfile': str(fname),
                        'sha256': sha256(data).hexdigest(),
                        'size': len(data),
                        'entropy': entropy_bytes(data),
                        'detected_magic': detect_magic(str(fname)) if os.path.exists(str(fname)) else None
                    })
    except Exception:
        pass

    # write manifest
    manifest_path = outdir / "manifest.json"
    manifest_data = {
        'target': str(target_path),
        'artifact_count': len(manifest),
        'artifacts': manifest
    }
    with open(manifest_path, 'w') as mf:
        json.dump(manifest_data, mf, indent=2)
    return manifest_path

def main():
    if len(sys.argv) < 2:
        print("Usage: forenscope-decode.py <file>")
        sys.exit(1)
    target = sys.argv[1]
    if not os.path.exists(target):
        print("File not found:", target)
        sys.exit(2)
    print("[*] Running ForenScope analyze() ...")
    report = analyze(target)  # reuses your forenscope.analyze
    print("[*] Analyze complete. Scanning for artifacts ...")
    manifest_path = scan_and_decode(report, target)
    print("[*] Done. Manifest:", manifest_path)
    with open(manifest_path) as mf:
        print(mf.read())

if __name__ == '__main__':
    main()
