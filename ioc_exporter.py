#!/usr/bin/env python3
import json, sys, os
from pathlib import Path

def export_iocs(report_path):
    with open(report_path) as f:
        data = json.load(f)
    iocs = data.get("indicators", {})
    out_path = Path(report_path).with_name("ioc_report.txt")
    with open(out_path, "w") as out:
        out.write(f"IOC Report for {data.get('path','unknown')}\n")
        out.write("="*60 + "\n\n")
        for key, values in iocs.items():
            out.write(f"[{key.upper()}]\n")
            for v in values: out.write(f"{v}\n")
            out.write("\n")
    print("IOC report saved:", out_path)

if __name__=="__main__":
    if len(sys.argv)<2:
        print("Usage: ioc_exporter.py <forenscope_report.json>")
        sys.exit(1)
    export_iocs(sys.argv[1])

