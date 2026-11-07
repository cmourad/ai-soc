#!/usr/bin/env python3
"""Build the console's bundled offline IP intelligence table.

The five regional registries publish country delegations for IPv4 and IPv6.
IPtoASN publishes routed ranges with origin ASN and network-owner descriptions
under the Open Data Commons Public Domain
Dedication and License 1.0 (PDDL-1.0):

    https://iptoasn.com/
    https://opendatacommons.org/licenses/pddl/1-0/

The country centroids used by the threat map come from the existing
country-codes-lat-long dataset. Generation downloads data, but the application
does not: it reads the committed table lazily on the first lookup.

Ranges are stored as base36 deltas and lengths. ASN labels are deduplicated and
referenced by a dense integer so the committed artifact stays substantially
smaller than the source TSV without adding a runtime dependency.

    python3 scripts/build_geo_table.py [cache-directory]

Writes console/server/src/intel/geo-table.txt. Refresh once or twice a year.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import sys
import urllib.request
from pathlib import Path

IP_TO_ASN = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
RIRS = {
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "arin": "https://ftp.ripe.net/pub/stats/arin/delegated-arin-extended-latest",
    "apnic": "https://ftp.ripe.net/pub/stats/apnic/delegated-apnic-extended-latest",
    "lacnic": "https://ftp.ripe.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.ripe.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}
CENTROIDS = "https://raw.githubusercontent.com/eesur/country-codes-lat-long/master/country-codes-lat-long-alpha3.json"

EXTRA_CENTROIDS = {
    "AX": ("Åland Islands", 60.2, 20.0),
    "BL": ("Saint Barthélemy", 17.9, -62.85),
    "BQ": ("Caribbean Netherlands", 12.18, -68.25),
    "CW": ("Curaçao", 12.17, -68.99),
    "MF": ("Saint Martin", 18.08, -63.05),
    "SS": ("South Sudan", 7.0, 30.0),
    "SX": ("Sint Maarten", 18.03, -63.05),
}

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "console" / "server" / "src" / "intel" / "geo-table.txt"
DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"

CountryRange = tuple[int, int, str]
AsnRange = tuple[int, int, int]


def b36(value: int) -> str:
    if value < 0:
        raise ValueError("base36 values must be non-negative")
    if value == 0:
        return "0"
    out = ""
    while value:
        value, rem = divmod(value, 36)
        out = DIGITS[rem] + out
    return out


def fetch(url: str, cache_dir: Path) -> bytes:
    cache = cache_dir / url.rsplit("/", 1)[-1]
    if cache.exists():
        return cache.read_bytes()
    with urllib.request.urlopen(url, timeout=300) as response:
        body = response.read()
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(body)
    return body


def parse_asn_ranges(body: bytes) -> tuple[list[AsnRange], list[AsnRange], dict[int, str]]:
    ipv4: list[AsnRange] = []
    ipv6: list[AsnRange] = []
    organizations: dict[int, str] = {}
    conflicts: set[int] = set()

    for raw in gzip.decompress(body).decode("utf-8", "replace").splitlines():
        parts = raw.split("\t", 4)
        if len(parts) != 5:
            continue
        start_text, end_text, asn_text, country, description = parts
        try:
            start_ip = ipaddress.ip_address(start_text)
            end_ip = ipaddress.ip_address(end_text)
            asn = int(asn_text)
        except ValueError:
            continue
        if asn <= 0 or start_ip.version != end_ip.version:
            continue
        start = int(start_ip)
        end = int(end_ip)
        if end < start:
            continue

        label = " ".join(description.split()) or "Unknown network"
        previous = organizations.setdefault(asn, label)
        if previous != label:
            conflicts.add(asn)
        target = ipv4 if start_ip.version == 4 else ipv6
        target.append((start, end, asn))

    if conflicts:
        print(
            f"warning: {len(conflicts)} ASNs had multiple descriptions; kept first",
            file=sys.stderr,
        )
    return merge_asns(ipv4), merge_asns(ipv6), organizations


def merge_asns(ranges: list[AsnRange]) -> list[AsnRange]:
    ranges.sort(key=lambda item: item[0])
    merged: list[AsnRange] = []
    for start, end, asn in ranges:
        if merged:
            old_start, old_end, old_asn = merged[-1]
            if start <= old_end:
                raise ValueError(f"overlapping source ranges at {start}")
            if start == old_end + 1 and asn == old_asn:
                merged[-1] = (old_start, end, asn)
                continue
        merged.append((start, end, asn))
    return merged


def parse_country_ranges(text: str) -> tuple[list[CountryRange], list[CountryRange]]:
    ipv4: list[CountryRange] = []
    ipv6: list[CountryRange] = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) < 5 or parts[2] not in {"ipv4", "ipv6"}:
            continue
        country, start_text, size_text = parts[1].upper(), parts[3], parts[4]
        if len(country) != 2 or country == "ZZ" or start_text == "*":
            continue
        try:
            if parts[2] == "ipv4":
                start = int(ipaddress.IPv4Address(start_text))
                end = start + int(size_text) - 1
                ipv4.append((start, end, country))
            else:
                network = ipaddress.IPv6Network(f"{start_text}/{int(size_text)}", strict=False)
                ipv6.append((int(network.network_address), int(network.broadcast_address), country))
        except ValueError:
            continue
    return ipv4, ipv6


def merge_countries(ranges: list[CountryRange]) -> list[CountryRange]:
    ranges.sort(key=lambda item: item[0])
    merged: list[CountryRange] = []
    for start, end, country in ranges:
        if merged:
            old_start, old_end, old_country = merged[-1]
            if start <= old_end:
                if country == old_country:
                    merged[-1] = (old_start, max(old_end, end), country)
                    continue
                if end <= old_end:
                    continue
                start = old_end + 1
            if start == old_end + 1 and country == old_country:
                merged[-1] = (old_start, end, country)
                continue
        merged.append((start, end, country))
    return merged


def encode_countries(ranges: list[CountryRange]) -> list[str]:
    starts: list[str] = []
    lengths: list[str] = []
    codes: list[str] = []
    cursor = 0
    for start, end, country in ranges:
        starts.append(b36(start - cursor))
        lengths.append(b36(end - start + 1))
        codes.append(country)
        cursor = end + 1
    return [" ".join(starts), " ".join(lengths), "".join(codes)]


def encode_asns(ranges: list[AsnRange], indexes: dict[int, int]) -> list[str]:
    starts: list[str] = []
    lengths: list[str] = []
    asns: list[str] = []
    cursor = 0
    for start, end, asn in ranges:
        starts.append(b36(start - cursor))
        lengths.append(b36(end - start + 1))
        asns.append(b36(indexes[asn]))
        cursor = end + 1
    return [" ".join(starts), " ".join(lengths), " ".join(asns)]


def main() -> int:
    cache_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".geo-cache"
    asn4, asn6, organizations = parse_asn_ranges(fetch(IP_TO_ASN, cache_dir))
    country4: list[CountryRange] = []
    country6: list[CountryRange] = []
    for name, url in RIRS.items():
        found4, found6 = parse_country_ranges(fetch(url, cache_dir).decode("utf-8", "replace"))
        print(f"{name}: {len(found4)} IPv4, {len(found6)} IPv6 delegations", file=sys.stderr)
        country4.extend(found4)
        country6.extend(found6)
    country4 = merge_countries(country4)
    country6 = merge_countries(country6)
    print(
        f"merged country: {len(country4)} IPv4, {len(country6)} IPv6; "
        f"ASN: {len(asn4)} IPv4, {len(asn6)} IPv6 ranges",
        file=sys.stderr,
    )

    centroids = json.loads(fetch(CENTROIDS, cache_dir).decode("utf-8"))["ref_country_codes"]
    countries = {
        entry["alpha2"]: {
            "name": entry["country"],
            "lat": round(float(entry["latitude"]), 2),
            "lon": round(float(entry["longitude"]), 2),
        }
        for entry in centroids
        if entry.get("alpha2")
    }
    for code, (name, lat, lon) in EXTRA_CENTROIDS.items():
        countries.setdefault(code, {"name": name, "lat": lat, "lon": lon})

    ordered_asns = sorted(organizations)
    indexes = {asn: index for index, asn in enumerate(ordered_asns)}
    labels = [f"AS{asn} {organizations[asn]}" for asn in ordered_asns]
    used = {country for _, _, country in [*country4, *country6]}
    missing = sorted(used - set(countries))
    if missing:
        print(f"no centroid for: {', '.join(missing)}", file=sys.stderr)

    lines = [
        "aisoc-ip-intel-v2",
        *encode_countries(country4),
        *encode_countries(country6),
        *encode_asns(asn4, indexes),
        *encode_asns(asn6, indexes),
        json.dumps(countries, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        json.dumps(labels, ensure_ascii=False, separators=(",", ":")),
    ]
    OUT.write_text("\n".join(lines) + "\n")
    print(
        f"wrote {OUT} ({OUT.stat().st_size / 1024 / 1024:.2f} MiB, "
        f"{len(labels)} ASN labels)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
