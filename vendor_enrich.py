#!/usr/bin/env python3

import re
import sys
from functools import lru_cache

sys.path.insert(0, "/usr/local/lib/omenrf")

from mac_vendor import lookup
from mac_acquire import acquire_mac

MAC_RE = re.compile(
    r'(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b'
)

IPV4_RE = re.compile(
    r'^(?:'
    r'(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.'
    r'){3}'
    r'(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$'
)

@lru_cache(maxsize=512)
def cached_mac_for_ip(ip):
    return acquire_mac(ip)

def enrich_mac(mac):
    r = lookup(mac)

    return {
        "mac": r.get("mac"),
        "vendor": r.get("vendor"),
        "manufacturer": r.get("vendor"),
        "vendor_brand": r.get("brand"),
        "vendor_source": r.get("source"),
        "vendor_confidence": r.get("confidence"),
        "vendor_prefix": r.get("prefix"),
        "vendor_prefix_bits": r.get("prefix_bits"),
        "locally_administered":
            r.get("locally_administered", False),
        "multicast":
            r.get("multicast", False),
    }

def find_existing_mac(obj):
    for key in (
        "mac",
        "mac_address",
        "macAddress",
        "bssid",
        "BSSID",
    ):
        value = obj.get(key)

        if isinstance(value, str):
            value = value.strip()

            if MAC_RE.fullmatch(value):
                return value

    return None

def find_ipv4(obj):
    for key in (
        "ip",
        "ip_address",
        "ipAddress",
        "host",
        "host_ip",
        "target",
        "address",
    ):
        value = obj.get(key)

        if isinstance(value, str):
            value = value.strip()

            if IPV4_RE.fullmatch(value):
                return value

    return None

def enrich_object(obj):
    if isinstance(obj, list):
        return [enrich_object(v) for v in obj]

    if not isinstance(obj, dict):
        return obj

    out = {
        k: enrich_object(v)
        for k, v in obj.items()
    }

    mac = find_existing_mac(out)

    if not mac:
        ip = find_ipv4(out)

        if ip:
            discovered = cached_mac_for_ip(ip)

            if discovered:
                mac = discovered
                out["mac"] = discovered
                out["mac_source"] = "Linux neighbor table"

    if not mac:
        return out

    info = enrich_mac(mac)

    if not out.get("vendor"):
        out["vendor"] = info["vendor"]

    if not out.get("manufacturer"):
        out["manufacturer"] = info["manufacturer"]

    out["vendor_brand"] = info["vendor_brand"]
    out["vendor_source"] = info["vendor_source"]
    out["vendor_confidence"] = info["vendor_confidence"]
    out["vendor_prefix"] = info["vendor_prefix"]
    out["vendor_prefix_bits"] = info["vendor_prefix_bits"]
    out["locally_administered"] = info["locally_administered"]
    out["multicast"] = info["multicast"]

    return out
