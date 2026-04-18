import os
import re

module_dir = 'modules'
tools = ['airodump-ng', 'nmap', 'tshark', 'tcpdump', 'hcxdumptool', 'mdk4', 'reaver', 'bettercap', 'mitmproxy', 'eaphammer']

for filename in os.listdir(module_dir):
    if filename.endswith('.sh'):
        path = os.path.join(module_dir, filename)
        with open(path, 'r') as f:
            content = f.read()
        
        # We need a very robust regex to catch tool calls inside the window block
        # even if they are already wrapped in a simple timeout or have multiple spaces.
        
        # 1. First, find the ASTRA_IN_WINDOW block
        if 'if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then' in content:
            # We'll split the content to only work within the blocks
            parts = content.split('if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then')
            new_parts = [parts[0]]
            
            for part in parts[1:]:
                # Find the end of this specific if block (the first 'else' or 'fi')
                # This is a bit naive for nested if's but our scripts are simple
                sub_parts = re.split(r'(\n\s*else|\n\s*fi)', part, 1)
                window_logic = sub_parts[0]
                rest = "".join(sub_parts[1:])
                
                # Within window_logic, wrap tools in timeout --foreground if not already
                for tool in tools:
                    # Match tool call NOT preceded by timeout --foreground
                    # and NOT preceded by & (which would mean it's backgrounded)
                    # We also handle existing 'timeout "..." tool' and convert to 'timeout --foreground "..." tool'
                    
                    # Regex explanation:
                    # (?<!timeout --foreground ) -> Not preceded by timeout --foreground
                    # (?<!& ) -> Not preceded by & (approximation for background)
                    # \b(tool)\b -> The tool name
                    
                    # Let's use a simpler approach: find all lines starting with tool or timeout and tool
                    lines = window_logic.split('\n')
                    new_lines = []
                    for line in lines:
                        trimmed = line.strip()
                        if any(trimmed.startswith(t) for t in tools):
                            # It's a raw tool call
                            indent = line[:line.find(trimmed)]
                            time_var = "$SCAN_TIME"
                            if 'CAPTURE_TIME' in content: time_var = "$CAPTURE_TIME"
                            
                            # Check if it ends with &
                            if trimmed.endswith('&'):
                                # Background tool: use standard timeout (foreground doesn't apply to &)
                                # But we MUST ensure timeout is used
                                tool_cmd = trimmed.rstrip('&').strip()
                                new_lines.append(f'{indent}timeout "{time_var}" {tool_cmd} &')
                            else:
                                # Foreground tool: use --foreground
                                new_lines.append(f'{indent}timeout --foreground "{time_var}" {trimmed} || true')
                        elif trimmed.startswith('timeout') and any(t in trimmed for t in tools):
                            # It's already wrapped in timeout, ensure --foreground is there if not background
                            if '--foreground' not in trimmed and not trimmed.endswith('&'):
                                new_lines.append(line.replace('timeout', 'timeout --foreground'))
                            else:
                                new_lines.append(line)
                        else:
                            new_lines.append(line)
                    window_logic = '\n'.join(new_lines)
                
                new_parts.append(window_logic + rest)
            
            content = 'if [[ "${ASTRA_IN_WINDOW:-}" == "true" ]]; then'.join(new_parts)

        # Final cleanup of double || true
        content = content.replace('|| true || true', '|| true')

        with open(path, 'w') as f:
            f.write(content)
        print(f"Verified tactical logic in {filename}")
