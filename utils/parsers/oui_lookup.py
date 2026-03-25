#!/usr/bin/env python3
import sys

# Extended OUI database for common wireless devices
OUI_DB = {
    # Apple
    "00:03:93": "Apple", "00:0A:95": "Apple", "00:0D:93": "Apple", "00:10:FA": "Apple",
    "00:16:CB": "Apple", "00:17:C4": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple",
    "00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple", "00:24:36": "Apple",
    "00:25:00": "Apple", "00:25:4B": "Apple", "00:25:BC": "Apple", "00:26:08": "Apple",
    "00:26:4A": "Apple", "00:26:B0": "Apple", "00:26:BB": "Apple", "3C:22:FB": "Apple",
    "F0:D5:BF": "Apple", "AC:BC:32": "Apple", "78:4F:43": "Apple", "A4:83:E7": "Apple",
    "DC:A9:04": "Apple", "70:56:81": "Apple", "14:7D:DA": "Apple", "D8:CF:9C": "Apple",
    
    # Samsung
    "00:00:F0": "Samsung", "00:02:D1": "Samsung", "00:07:AB": "Samsung", "00:0D:E6": "Samsung",
    "00:12:47": "Samsung", "00:12:FB": "Samsung", "00:13:77": "Samsung", "00:15:99": "Samsung",
    "00:15:B9": "Samsung", "00:16:6B": "Samsung", "00:16:DB": "Samsung", "00:17:C9": "Samsung",
    "00:17:D1": "Samsung", "00:18:AF": "Samsung", "00:19:2D": "Samsung", "00:1A:8A": "Samsung",
    "54:27:1E": "Samsung", "34:17:EB": "Samsung", "B4:AE:2B": "Samsung", "BC:72:B1": "Samsung",
    
    # Intel (WiFi cards)
    "00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel", "00:08:A1": "Intel",
    "00:0C:F1": "Intel", "00:0E:35": "Intel", "00:13:02": "Intel", "00:13:E8": "Intel",
    "00:15:00": "Intel", "00:16:6F": "Intel", "00:16:EA": "Intel", "00:18:DE": "Intel",
    "00:19:D1": "Intel", "00:1B:77": "Intel", "00:1C:BF": "Intel", "00:1D:E0": "Intel",
    "00:1E:64": "Intel", "00:1E:65": "Intel", "00:21:5C": "Intel", "00:21:6A": "Intel",
    "74:DA:38": "Intel", "E0:3F:49": "Intel", "34:97:F6": "Intel", "4C:D5:77": "Intel",
    
    # Cisco
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco", "00:01:63": "Cisco",
    "00:01:64": "Cisco", "00:01:96": "Cisco", "00:01:97": "Cisco", "00:01:C7": "Cisco",
    "00:01:C9": "Cisco", "00:02:16": "Cisco", "00:02:17": "Cisco", "00:02:4A": "Cisco",
    "00:1E:68": "Cisco", "D4:BE:D9": "Cisco", "00:50:B6": "Cisco", "00:27:0D": "Cisco",
    
    # Microsoft
    "00:03:FF": "Microsoft", "00:12:5A": "Microsoft", "00:15:5D": "Microsoft", "00:17:FA": "Microsoft",
    "00:1D:D8": "Microsoft", "00:22:48": "Microsoft", "00:25:AE": "Microsoft", "00:50:F2": "Microsoft",
    "94:65:9C": "Microsoft", "50:C7:BF": "Microsoft", "9C:B6:D0": "Microsoft", "28:18:78": "Microsoft",
    
    # Google
    "00:1A:11": "Google", "3C:5A:B4": "Google", "F4:F5:D8": "Google", "D8:EB:97": "Google",
    "00:23:68": "Google", "84:8F:69": "Google", "50:7B:9D": "Google", "1C:53:F9": "Google",
    
    # Amazon
    "00:BB:3A": "Amazon", "18:74:2E": "Amazon", "34:D2:70": "Amazon", "40:B4:CD": "Amazon",
    "44:07:0B": "Amazon", "44:65:0D": "Amazon", "50:DC:E7": "Amazon", "68:37:E9": "Amazon",
    "EC:FA:BC": "Amazon", "2C:6E:85": "Amazon",
    
    # Dell
    "00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell", "00:0D:56": "Dell",
    "00:0F:1F": "Dell", "00:11:43": "Dell", "00:12:3F": "Dell", "00:13:72": "Dell",
    "F8:75:A4": "Dell", "C8:1F:66": "Dell", "00:21:70": "Dell", "24:B6:FD": "Dell",
    
    # HP
    "00:08:02": "Hewlett-Packard", "00:0B:CD": "Hewlett-Packard", "00:0E:7F": "Hewlett-Packard",
    "00:0F:20": "Hewlett-Packard", "00:10:83": "Hewlett-Packard", "00:11:0A": "Hewlett-Packard",
    "B0:5A:DA": "Hewlett-Packard", "A0:8C:FD": "Hewlett-Packard", "30:24:32": "Hewlett-Packard",
    
    # Lenovo
    "00:12:FE": "Lenovo", "00:16:36": "Lenovo", "00:1A:64": "Lenovo", "00:1B:44": "Lenovo",
    "00:22:6B": "Lenovo", "00:24:D7": "Lenovo", "60:67:20": "Lenovo", "70:F3:95": "Lenovo",
    
    # Huawei
    "00:18:82": "Huawei", "00:1E:10": "Huawei", "00:25:9E": "Huawei", "00:46:4B": "Huawei",
    "E8:6A:64": "Huawei", "14:AB:C5": "Huawei", "D8:B1:2A": "Huawei", "24:DF:6A": "Huawei",
    
    # Ubiquiti
    "00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti", "68:72:51": "Ubiquiti", "70:3A:CB": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti", "B4:FB:E4": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    
    # Aruba
    "00:0B:86": "Aruba", "00:1A:1E": "Aruba", "04:BD:88": "Aruba", "20:4C:03": "Aruba",
    "6C:F3:7F": "Aruba", "94:B4:0F": "Aruba", "AC:A3:1E": "Aruba",
    
    # Meraki
    "00:18:0A": "Meraki", "0C:8D:DB": "Meraki", "88:15:44": "Meraki", "E0:55:3D": "Meraki",
    "34:56:FE": "Meraki",
    
    # Realtek
    "00:E0:4C": "Realtek", "28:6C:07": "Realtek", "48:5D:60": "Realtek", "52:54:00": "Realtek",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation", "E4:5F:01": "Raspberry Pi Foundation",
}

def lookup(mac):
    # Standardize input
    mac = mac.upper().replace("-", ":")
    prefix = mac[:8]
    
    # Check for random MACs (Locally Administered Address)
    # If the second character of the first byte is 2, 6, A, or E
    # x2:xx:xx:xx:xx:xx, x6:..., xA:..., xE:...
    if len(mac) >= 2:
        try:
            first_byte = int(mac[:2], 16)
            if first_byte & 0x02:
                return "Randomized/Private MAC"
        except ValueError:
            pass

    return OUI_DB.get(prefix, f"Unknown ({prefix})")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: oui_lookup.py <MAC>")
        sys.exit(1)
    print(lookup(sys.argv[1]))
