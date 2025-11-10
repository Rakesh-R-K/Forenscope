#!/usr/bin/env python3
"""
ForenScope — lightweight forensic file analyzer (single-file)
Usage:
    python3 forenscope.py analyze <file> [-o report.json] [--strings-min 4] [--max-bytes 10485760]
"""
import sys, os, argparse, json, math, re, base64, binascii
from hashlib import md5, sha1, sha256

# Optional imaging
try:
    from PIL import Image, ExifTags
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

# helpers
def human(n):
    for unit in ['B','KB','MB','GB','TB']:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"

def chunked_hashes(path, chunk_size=4*1024*1024):
    h_md5 = md5(); h_sha1 = sha1(); h_sha256 = sha256()
    total = 0
    with open(path, 'rb') as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            total += len(b)
            h_md5.update(b); h_sha1.update(b); h_sha256.update(b)
    return {'md5': h_md5.hexdigest(), 'sha1': h_sha1.hexdigest(), 'sha256': h_sha256.hexdigest(), 'size': total}

# file magic sniff (very small set)
MAGIC_TABLE = [
    (b'\x50\x4B\x03\x04', 'zip'),
    (b'\x89PNG\r\n\x1a\n', 'png'),
    (b'\xff\xd8\xff', 'jpeg'),
    (b'%PDF-', 'pdf'),
    (b'PK\x03\x04', 'zip'),
    (b'Rar!\x1A\x07\x00', 'rar'),
    (b'\x7fELF', 'elf'),
    (b'GIF87a', 'gif'),
    (b'GIF89a', 'gif'),
    (b'BZh', 'bzip2'),
    (b'\x1f\x8b', 'gzip'),
    (b'NTLMSSP', 'ntlmssp'),
]

def detect_magic(path, max_read=4096):
    with open(path, 'rb') as f:
        head = f.read(max_read)
    for sig, typename in MAGIC_TABLE:
        if head.startswith(sig):
            return typename
    # fallback: textual vs binary heuristic
    text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20,0x100)))
    nontext = sum(1 for b in head if b not in text_chars)
    if nontext / max(1, len(head)) > 0.30:
        return 'binary'
    return 'text'

# entropy
def shannon_entropy(data: bytes):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    ln2 = math.log(2)
    length = len(data)
    for v in freq.values():
        p = v / length
        ent -= p * (math.log(p) / ln2)
    return ent  # bits per symbol (0..8 for bytes)

def file_entropy(path, sample_bytes=262144):
    size = os.path.getsize(path)
    to_read = min(sample_bytes, size)
    with open(path, 'rb') as f:
        data = f.read(to_read)
    return shannon_entropy(data)

# printable strings
PRINT_RE = re.compile(rb'[\x20-\x7e]{%d,}')
def extract_strings(path, min_len=4, max_bytes=10*1024*1024):
    results = []
    read = 0
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(64*1024)
            if not chunk:
                break
            read += len(chunk)
            for m in PRINT_RE.finditer(chunk):
                s = m.group().decode('latin1', errors='ignore')
                if len(s) >= min_len:
                    results.append(s)
            if read >= max_bytes:
                break
    return results

# base64/hex detection heuristics
B64_RE = re.compile(r'^[A-Za-z0-9+/=\\s]{40,}$')
HEX_RE = re.compile(r'^[0-9a-fA-F\\s]{40,}$')

def try_decode_b64(s):
    try:
        # strip whitespace/newlines
        cleaned = re.sub(r'\\s+', '', s)
        b = base64.b64decode(cleaned, validate=True)
        return b
    except Exception:
        return None

def try_decode_hex(s):
    try:
        cleaned = re.sub(r'\\s+', '', s)
        b = binascii.unhexlify(cleaned)
        return b
    except Exception:
        return None

# quick indicators (IP/email/url)
IP_RE = re.compile(r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b')
EMAIL_RE = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+')
URL_RE = re.compile(r'https?://[\\w\\-\\./:?&=#%]+')

def analyze(path, strings_min=4, max_bytes_for_strings=10*1024*1024):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    info = {}
    info['path'] = os.path.abspath(path)
    info['size_bytes'] = os.path.getsize(path)
    info['human_size'] = human(info['size_bytes'])
    info.update(chunked_hashes(path))
    info['magic'] = detect_magic(path)
    info['entropy_sample'] = file_entropy(path)
    # basic strings
    strs = extract_strings(path, min_len=strings_min, max_bytes=max_bytes_for_strings)
    info['strings_count'] = len(strs)
    info['sample_strings'] = strs[:50]
    # indicators
    ips = set(); emails = set(); urls = set()
    for s in strs[:2000]:
        for ip in IP_RE.findall(s):
            ips.add(ip)
        for email in EMAIL_RE.findall(s):
            emails.add(email)
        for url in URL_RE.findall(s):
            urls.add(url)
    info['indicators'] = {'ips': sorted(ips), 'emails': sorted(emails), 'urls': sorted(urls)}
    # try detect large base64/hex blocks in strings
    b64_candidates = []
    hex_candidates = []
    for s in strs:
        if len(s) < 40: continue
        if B64_RE.match(s):
            decoded = try_decode_b64(s)
            if decoded:
                b64_candidates.append({'orig_len': len(s), 'decoded_len': len(decoded)})
        if HEX_RE.match(s):
            decoded = try_decode_hex(s)
            if decoded:
                hex_candidates.append({'orig_len': len(s), 'decoded_len': len(decoded)})
    info['b64_candidates'] = b64_candidates[:10]
    info['hex_candidates'] = hex_candidates[:10]

    # image EXIF (optional)
    if PIL_AVAILABLE and info['magic'] in ('jpeg','png','gif'):
        try:
            img = Image.open(path)
            info['image_format'] = img.format
            info['image_mode'] = img.mode
            info['image_size'] = img.size
            exif = {}
            try:
                raw_exif = img._getexif()
                if raw_exif:
                    for k, v in raw_exif.items():
                        tag = ExifTags.TAGS.get(k, k)
                        exif[tag] = v
            except Exception:
                pass
            info['exif'] = exif
        except Exception as e:
            info['image_error'] = str(e)

    return info

def main():
    ap = argparse.ArgumentParser(prog='forenscope', description='ForenScope — lightweight forensic file analyzer')
    sub = ap.add_subparsers(dest='cmd')
    p = sub.add_parser('analyze', help='Analyze a file')
    p.add_argument('file', help='Path to file')
    p.add_argument('-o','--out', help='Write JSON report')
    p.add_argument('--strings-min', type=int, default=4)
    p.add_argument('--max-bytes', type=int, default=10*1024*1024, help='Max bytes to scan for strings')
    args = ap.parse_args()
    if args.cmd == 'analyze':
        rpt = analyze(args.file, strings_min=args.strings_min, max_bytes_for_strings=args.max_bytes)
        print(json.dumps(rpt, indent=2, default=str))
        if args.out:
            with open(args.out, 'w') as f:
                json.dump(rpt, f, indent=2)
    else:
        ap.print_help()

if __name__ == '__main__':
    main()

