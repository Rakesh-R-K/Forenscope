#!/usr/bin/env python3
import os, sys, json, re, base64, binascii
from pathlib import Path
from hashlib import sha256
from math import log2
from forenscope import analyze, detect_magic
from type_mapper import get_extension

MIN_CAND_LENGTH = 5
STRINGS_SCAN_LIMIT = 2000
ARTIFACTS_DIR = Path.cwd() / "artifacts"
B64_RE = re.compile(r'^[A-Za-z0-9+/=\s]{5,}$')
HEX_RE = re.compile(r'^[0-9a-fA-F\s]{5,}$')

def entropy_bytes(data: bytes):
    if not data: return 0.0
    freq = {}; l=len(data); ent=0
    for b in data: freq[b]=freq.get(b,0)+1
    for v in freq.values():
        p=v/l; ent-=p*(log2(p) if p>0 else 0)
    return ent

def try_decode_b64(s):
    try:
        cleaned = re.sub(r'\s+', '', s)
        return base64.b64decode(cleaned, validate=True)
    except Exception: return None

def try_decode_hex(s):
    try:
        cleaned = re.sub(r'\s+', '', s)
        if len(cleaned)%2==1: cleaned='0'+cleaned
        return binascii.unhexlify(cleaned)
    except Exception: return None

def safe_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'wb') as f: f.write(data)

def artifact_name(base_dir: Path, prefix: str, idx: int, ext: str = ".bin"):
    return base_dir / f"{prefix}_{idx}{ext}"

def scan_and_decode(report, target_path: Path):
    base = Path(target_path).stem
    outdir = ARTIFACTS_DIR / base
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = []; idx=0

    # Enhanced raw scan for Base64/Hex
    raw = Path(target_path).read_bytes()
    raw_text = raw.decode('utf-8', errors='ignore')
    for m in re.finditer(r'([A-Za-z0-9+/=]{5,})', raw_text):
        s = m.group(1)
        data = try_decode_b64(s)
        if not data: data = try_decode_hex(s)
        if data:
            idx+=1
            ext = get_extension(detect_magic(str(target_path)))
            fname = artifact_name(outdir, 'decoded', idx, ext)
            safe_write(fname, data)
            manifest.append({
                'source': 'raw_scan',
                'string_snippet': s[:60],
                'outfile': str(fname),
                'sha256': sha256(data).hexdigest(),
                'size': len(data),
                'entropy': entropy_bytes(data),
                'detected_magic': detect_magic(str(fname))
            })

    manifest_path = outdir / "manifest.json"
    with open(manifest_path,'w') as f:
        json.dump({'target': str(target_path), 'artifact_count': len(manifest), 'artifacts': manifest}, f, indent=2)
    return manifest_path

def main():
    if len(sys.argv)<2:
        print("Usage: forenscope-decode.py <file>"); sys.exit(1)
    target=sys.argv[1]
    if not os.path.exists(target):
        print("File not found:",target); sys.exit(2)
    print("[*] Running ForenScope analyze() ...")
    analyze(target)  # not used further here, but ensures analyzer runs
    print("[*] Analyze complete. Scanning for artifacts ...")
    manifest_path = scan_and_decode({}, target)
    print("[*] Done. Manifest:", manifest_path)
    with open(manifest_path) as f: print(f.read())

if __name__=='__main__':
    main()
