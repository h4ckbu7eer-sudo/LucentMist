#!/usr/bin/env python3
"""Convert selected Rapid7 Recog XML datasets into LucentMist's embedded runtime format.

The input must be an official Recog checkout. The generated file is deterministic and
contains attribution per rule; LucentMist does not fetch fingerprints at runtime.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET


SOURCES = {
    "http_servers.xml": "http_server",
    "http_xpoweredby.xml": "http_powered_by",
    "ssh_banners.xml": "ssh",
    "smtp_banners.xml": "smtp",
    "pop_banners.xml": "pop",
    "imap_banners.xml": "imap",
    "dns_versionbind.xml": "dns",
    "ftp_banners.xml": "ftp",
    "mysql_banners.xml": "mysql",
}


def param(fingerprint: ET.Element, name: str) -> ET.Element | None:
    return next((p for p in fingerprint.findall("param") if p.get("name") == name), None)


def convert(xml_dir: Path) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    for filename, scope in SOURCES.items():
        root = ET.parse(xml_dir / filename).getroot()
        for ordinal, fingerprint in enumerate(root.findall("fingerprint"), start=1):
            vendor = param(fingerprint, "service.vendor")
            product = param(fingerprint, "service.product")
            if vendor is None or product is None:
                continue
            version = param(fingerprint, "service.version")
            cpe = param(fingerprint, "service.cpe23")
            rules.append({
                "sourceFile": filename,
                "sourceOrdinal": ordinal,
                "scope": scope,
                "description": (fingerprint.findtext("description") or "").strip(),
                "pattern": fingerprint.get("pattern", ""),
                "ignoreCase": fingerprint.get("flags") == "REG_ICASE",
                "vendor": vendor.get("value", ""),
                "product": product.get("value", ""),
                "versionPosition": int(version.get("pos", "0")) if version is not None else 0,
                "versionValue": version.get("value") if version is not None else None,
                "cpeTemplate": cpe.get("value") if cpe is not None else None,
            })
    return rules


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("recog_xml", type=Path, help="Path to the official Recog xml directory")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rules = convert(args.recog_xml)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "upstream": "https://github.com/rapid7/recog",
        "upstreamCommit": "d3d20938da9f5f1e442c2419fe6c30cd651b6878",
        "license": "BSD-2-Clause",
        "sourceFiles": list(SOURCES),
        "rules": rules,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"generated {len(rules)} rules")


if __name__ == "__main__":
    main()
