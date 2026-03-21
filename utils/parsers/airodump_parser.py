#!/usr/bin/env python3
"""
Airodump-ng CSV Parser
Reads an airodump-ng CSV file and outputs a clean JSON array of discovered networks.
This avoids brittle Bash text processing.
"""
import sys
import json

def parse_airodump_csv(filepath):
    networks = []
    in_ap_section = False
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith("BSSID, First time seen"):
                    in_ap_section = True
                    continue
                
                if line.startswith("Station MAC"):
                    # Station section started, we are done with APs
                    break
                
                if in_ap_section:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        bssid = parts[0]
                        if bssid == "BSSID" or len(bssid) != 17:
                            continue
                            
                        channel = parts[3]
                        privacy = parts[5]
                        cipher = parts[6]
                        auth = parts[7]
                        power = parts[8]
                        beacons = parts[9]
                        essid = parts[13] if len(parts) > 13 else ""
                        
                        encryption = privacy
                        if cipher and cipher != " ":
                            encryption += f"/{cipher}"
                        if auth and auth != " ":
                            encryption += f"/{auth}"
                            
                        is_hidden = not essid.strip()
                        if is_hidden:
                            essid = "<HIDDEN>"
                            
                        networks.append({
                            "bssid": bssid,
                            "ssid": essid,
                            "channel": channel,
                            "encryption": encryption,
                            "signal": power,
                            "beacons": beacons,
                            "hidden": is_hidden
                        })
                        
        print(json.dumps(networks, indent=2))
        return 0
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 airodump_parser.py <file.csv>", file=sys.stderr)
        sys.exit(1)
    sys.exit(parse_airodump_csv(sys.argv[1]))
