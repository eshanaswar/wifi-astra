#!/usr/bin/env python3
import sys
import json

# Top common wireless vendors
OUI_DB = {
    "00:03:93": "Apple", "00:0A:95": "Apple", "00:0D:93": "Apple", "00:17:C4": "Apple",
    "3C:22:FB": "Apple", "F0:D5:BF": "Apple", "AC:BC:32": "Apple", "78:4F:43": "Apple",
    "A4:83:E7": "Apple", "DC:A9:04": "Apple", "70:56:81": "Apple", "14:7D:DA": "Apple",
    "F8:75:A4": "Dell", "C8:1F:66": "Dell", "00:21:70": "Dell", "24:B6:FD": "Dell",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "B0:5A:DA": "Hewlett-Packard", "A0:8C:FD": "Hewlett-Packard", "30:24:32": "Hewlett-Packard",
    "00:1E:68": "Cisco", "D4:BE:D9": "Cisco", "00:50:B6": "Cisco",
    "00:1B:44": "Lenovo", "00:22:6B": "Lenovo", "00:24:D7": "Lenovo",
    "54:27:1E": "Samsung", "34:17:EB": "Samsung", "B4:AE:2B": "Samsung",
    "E8:6A:64": "Huawei", "14:AB:C5": "Huawei", "D8:B1:2A": "Huawei",
    "28:6C:07": "Realtek", "00:E0:4C": "Realtek", "48:5D:60": "Realtek",
    "94:65:9C": "Microsoft", "50:C7:BF": "Microsoft", "9C:B6:D0": "Microsoft",
    "74:DA:38": "Intel", "E0:3F:49": "Intel", "34:97:F6": "Intel",
    "00:23:68": "Google", "84:8F:69": "Google", "50:7B:9D": "Google",
    "EC:FA:BC": "Amazon", "2C:6E:85": "Amazon", "44:07:0B": "Amazon",
    "00:27:22": "Ubiquiti", "24:A4:3C": "Ubiquiti", "70:3A:CB": "Ubiquiti",
    "00:0B:86": "Aruba", "00:1A:1E": "Aruba", "20:4C:03": "Aruba",
    "34:56:FE": "Meraki", "0C:8D:DB": "Meraki", "88:15:44": "Meraki",
}

def lookup(mac):
    mac = mac.upper().replace("-", ":")
    prefix = mac[:8]
    return OUI_DB.get(prefix, f"Unknown ({prefix})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: oui_lookup.py <MAC>")
        sys.exit(1)
    print(lookup(sys.argv[1]))
