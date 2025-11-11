#!/usr/bin/env python3
"""
ForenScope — Lightweight Forensic File Analyzer
"""
import sys, os, argparse, json, math, re, base64, binascii
from hashlib import md5, sha1, sha256

try:
    from PIL import Image, ExifTags
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False


# ──────────────────────────── HELPERS ────────────────────────────
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
            if not b: break
            total += len(b)
            h_md5.update(b); h_sha1.update(b); h_sha256.update(b)
    return {'md5': h_md5.hexdigest(), 'sha1': h_sha1.hexdigest(), 'sha256': h_sha256.hexdigest(), 'size': total}


MAGIC_TABLE = [
    (b'\x50\x4B\x03\x04', 'zip'),
    (b'\x89PNG\r\n\x1a\n', 'png'),
    (b'\xff\xd8\xff', 'jpeg'),
    (b'%PDF-', 'pdf'),
    (b'Rar!\x1A\x07\x00', 'rar'),
    (b'\x7fELF', 'elf'),
    (b'GIF87a', 'gif'),
    (b'GIF89a', 'gif'),
    (b'BZh', 'bzip2'),
    (b'\x1f\x8b', 'gzip'),
]


def detect_magic(path, max_read=4096):
    with open(path, 'rb') as f:
        head = f.read(max_read)
    if not head:
        return 'empty'
    for sig, typename in MAGIC_TABLE:
        if head.startswith(sig):
            return typename
    text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20,0x100)))
    nontext = sum(1 for b in head if b not in text_chars)
    if all(32 <= b < 127 or b in (10, 13) for b in head):
        return 'text'
    if nontext / max(1, len(head)) > 0.30:
        return 'binary'
    return 'text'


def shannon_entropy(data: bytes):
    if not data: return 0.0
    freq = {}
    for b in data: freq[b] = freq.get(b,0)+1
    ent = 0.0; ln2 = math.log(2); length = len(data)
    for v in freq.values():
        p = v/length; ent -= p*(math.log(p)/ln2)
    return ent


def file_entropy(path, sample_bytes=262144):
    size = os.path.getsize(path)
    to_read = min(sample_bytes, size)
    with open(path, 'rb') as f: data = f.read(to_read)
    return shannon_entropy(data)


PRINT_RE = re.compile(rb'[\x20-\x7e]{4,}')
def extract_strings(path, min_len=4, max_bytes=10*1024*1024):
    results = []
    with open(path, 'rb') as f:
        data = f.read(max_bytes)
        for m in PRINT_RE.finditer(data):
            s = m.group().decode('latin1', errors='ignore')
            if len(s) >= min_len:
                results.append(s)
    return results


IP_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
EMAIL_RE = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
URL_RE = re.compile(r'https?://[\w\-/\.?&=#%]+')


# ──────────────────────────── MAIN ANALYZE ────────────────────────────
def analyze(path, strings_min=4, max_bytes_for_strings=10*1024*1024):
    if not os.path.exists(path): raise FileNotFoundError(path)
    info = {'path': os.path.abspath(path)}
    info.update(chunked_hashes(path))
    info['human_size'] = human(info['size'])
    info['magic'] = detect_magic(path)
    info['entropy_sample'] = file_entropy(path)

    strs = extract_strings(path, min_len=strings_min, max_bytes=max_bytes_for_strings)
    info['strings_count'] = len(strs)
    info['sample_strings'] = strs[:50]

    ips = set(); emails = set(); urls = set()
    for s in strs[:2000]:
        ips.update(IP_RE.findall(s))
        emails.update(EMAIL_RE.findall(s))
        urls.update(URL_RE.findall(s))
    info['indicators'] = {'ips': sorted(ips), 'emails': sorted(emails), 'urls': sorted(urls)}

    # EXIF
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
                    for k,v in raw_exif.items():
                        tag = ExifTags.TAGS.get(k,k); exif[tag]=v
            except Exception: pass
            info['exif']=exif
        except Exception as e: info['image_error']=str(e)
    return info


def main():
    ap = argparse.ArgumentParser(description='ForenScope — Lightweight Forensic Analyzer')
    p = ap.add_subparsers(dest='cmd')
    q = p.add_parser('analyze'); q.add_argument('file'); q.add_argument('-o','--out')
    args = ap.parse_args()
    if args.cmd == 'analyze':
        rpt = analyze(args.file)
        print(json.dumps(rpt, indent=2, default=str))
        if args.out:
            with open(args.out,'w') as f: json.dump(rpt,f,indent=2,default=str)
    else:
        ap.print_help()

if __name__=='__main__':
    main()
