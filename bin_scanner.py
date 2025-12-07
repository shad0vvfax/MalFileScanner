#!/usr/bin/env python3
"""
Binary String Scanner - Analyzes binaries for potentially suspicious strings
Useful for malware analysis and security research
"""

import re
import sys
import argparse
import hashlib
from pathlib import Path
from collections import Counter

# Common suspicious string patterns
SUSPICIOUS_PATTERNS = {
    'IP Addresses': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'URLs': r'https?://[^\s<>"{}|\\^`\[\]]+',
    'Email Addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Registry Keys': r'HKEY_[A-Z_]+\\[^\x00]+',
    'File Paths': r'[A-Za-z]:\\(?:[^\x00\\/:*?"<>|\r\n]+\\)+[^\x00\\/:*?"<>|\r\n]+',
    'Shell Commands': r'(?:cmd\.exe|powershell\.exe|bash|sh)(?:\s+[-/][^\x00]+|\s+[A-Za-z0-9_]+\.(?:bat|ps1|sh|py))',
    'Suspicious Scripts': r'(?:wget|curl|invoke-webrequest|iwr|downloadstring|downloadfile)\s+http',
}

# SQL Injection patterns
SQL_INJECTION_PATTERNS = {
    'SQL Comments (Suspicious)': r'(?:--|#)\s*(?:union\s+select|drop\s+table|delete\s+from|exec|script\s*>|javascript:|alert\()',
    'Union-Based': r"(?i)\bunion\s+(?:all\s+)?select\s+.+\s+from\s+",
    'Boolean-Based Blind': r"(?i)(?:'\s*(?:and|or)\s*'?\d+|and\s+\d+\s*=\s*\d+\s+--)",
    'Time-Based Blind': r"(?i)(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(\s*\d+",
    'Stacked Queries': r";\s*(?:drop\s+table|delete\s+from|exec|execute)\s+",
    'String Concat Injection': r"(?i)(?:concat|group_concat)\s*\([^)]*select",
    'SQL File Operations': r"(?i)(?:load_file|into\s+(?:outfile|dumpfile))\s*\(",
    'Information Schema Access': r"(?i)(?:union|select).*information_schema\.(?:tables|columns)",
}

# Suspicious keywords
SUSPICIOUS_KEYWORDS = [
    'keylogger', 'backdoor', 'ransomware', 'cryptolocker', 'cryptor', 'stealer', 
    'trojan.downloader', 'trojan-downloader', 'virus.', 'worm.', 'rootkit',
    'mimikatz', 'procdump', 'hashdump', 'secretsdump', 'lazagne',
    'bypass uac', 'bypass amsi', 'bypass defender', 'disable defender',
    'reverse_shell', 'bind_shell', 'meterpreter', 'cobalt_strike', 'cobaltstrike',
    'privilege_escalation', 'privesc', 'impersonate_token',
    'invoke-mimikatz', 'invoke-bloodhound', 'powersploit'
]

# Privilege escalation indicators
PRIVESC_PATTERNS = {
    # Windows privilege escalation
    'Windows Token Manipulation': [
        b'SeDebugPrivilege', b'SeImpersonatePrivilege', b'SeAssignPrimaryTokenPrivilege',
        b'SeTcbPrivilege', b'SeBackupPrivilege', b'SeRestorePrivilege',
        b'SeLoadDriverPrivilege', b'SeTakeOwnershipPrivilege'
    ],
    'Windows UAC Bypass': [
        b'eventvwr.exe', b'fodhelper.exe', b'computerdefaults.exe',
        b'sdclt.exe', b'SilentCleanup', b'DiskCleanup',
        b'HKCU\\Software\\Classes\\ms-settings', b'HKCU\\Software\\Classes\\mscfile'
    ],
    'Windows Service Abuse': [
        b'CreateService', b'OpenSCManager', b'StartService',
        b'ChangeServiceConfig', b'sc.exe create', b'sc.exe config',
        b'binPath', b'ImagePath'
    ],
    'Windows Registry Persistence': [
        b'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        b'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        b'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        b'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'
    ],
    'Windows Scheduled Tasks': [
        b'schtasks.exe', b'schtasks /create', b'at.exe',
        b'\\Microsoft\\Windows\\TaskScheduler', b'Register-ScheduledTask'
    ],
    
    # Linux privilege escalation
    'Linux SUID/SUDO': [
        b'chmod +s', b'chmod 4755', b'chmod u+s',
        b'/etc/sudoers', b'NOPASSWD', b'sudo -l',
        b'find / -perm -4000', b'find / -perm -u=s'
    ],
    'Linux Capabilities': [
        b'setcap', b'getcap', b'cap_setuid', b'cap_setgid',
        b'cap_dac_override', b'cap_sys_admin', b'cap_sys_ptrace'
    ],
    'Linux Cron Jobs': [
        b'/etc/crontab', b'/etc/cron.d/', b'/var/spool/cron',
        b'crontab -e', b'crontab -l', b'@reboot'
    ],
    'Linux Kernel Exploits': [
        b'dirty_cow', b'dirtycow', b'overlayfs', b'pkexec',
        b'pwnkit', b'/proc/self/mem', b'/proc/self/environ'
    ],
    
    # Cross-platform
    'DLL/SO Injection': [
        b'LoadLibrary', b'dlopen', b'LD_PRELOAD', b'LD_LIBRARY_PATH',
        b'DLL hijacking', b'side-loading', b'.dll.', b'.so.'
    ],
    'Process Injection': [
        b'CreateRemoteThread', b'NtCreateThreadEx', b'RtlCreateUserThread',
        b'QueueUserAPC', b'SetWindowsHookEx', b'ptrace', b'process_vm_writev'
    ],
    'Credential Access': [
        b'lsass.exe', b'SAM', b'SYSTEM', b'SECURITY',
        b'mimikatz', b'procdump', b'/etc/shadow', b'/etc/passwd',
        b'hashdump', b'secretsdump', b'LaZagne'
    ],
}

# Common shellcode signatures and patterns
SHELLCODE_SIGNATURES = {
    'NOP Sled': b'\x90' * 10,  # 10+ consecutive NOPs
    'Int 0x80 (Linux syscall)': b'\xcd\x80',
    'Syscall (x64)': b'\x0f\x05',
    'JMP ESP': b'\xff\xe4',
    'JMP EAX': b'\xff\xe0',
    'CALL ESP': b'\xff\xd4',
    'PUSH/RET': b'\x50\xc3',
    'GetPC (x86)': b'\xe8\x00\x00\x00\x00',  # CALL $+5
}

# API calls commonly used in shellcode
SHELLCODE_APIS = [
    b'LoadLibraryA', b'LoadLibraryW', b'GetProcAddress',
    b'VirtualAlloc', b'VirtualProtect', b'CreateProcessA',
    b'CreateProcessW', b'WinExec', b'URLDownloadToFileA',
    b'ShellExecuteA', b'ShellExecuteW', b'CreateThread',
    b'CreateRemoteThread', b'WriteProcessMemory', b'kernel32',
    b'ntdll', b'ws2_32', b'WSAStartup', b'socket', b'connect'
]

def extract_strings(file_path, min_length=4, encoding='ascii'):
    """Extract printable strings from a binary file."""
    strings = []
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
        if encoding == 'ascii':
            pattern = b'[ -~]{' + str(min_length).encode() + b',}'
            matches = re.findall(pattern, data)
            strings = [s.decode('ascii', errors='ignore') for s in matches]
        elif encoding == 'unicode':
            pattern = b'(?:[ -~]\x00){' + str(min_length).encode() + b',}'
            matches = re.findall(pattern, data)
            strings = [s.decode('utf-16le', errors='ignore') for s in matches]
            
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        
    return strings

def scan_for_patterns(strings):
    """Scan strings for suspicious patterns."""
    findings = {}
    
    # Scan general suspicious patterns
    for category, pattern in SUSPICIOUS_PATTERNS.items():
        matches = []
        for s in strings:
            found = re.findall(pattern, s, re.IGNORECASE)
            matches.extend(found)
        
        if matches:
            # Filter IP addresses to remove OIDs (certificate identifiers)
            if category == 'IP Addresses':
                # Valid IPs shouldn't have leading zeros or start with 0.x or 1.x typically for OIDs
                filtered_matches = []
                for ip in matches:
                    octets = ip.split('.')
                    # Check if it looks like a real IP (not an OID)
                    # OIDs often have single digit octets like 1.3.x.x or 2.5.x.x
                    if (octets[0] not in ['1', '2'] or 
                        (octets[0] in ['1', '2'] and int(octets[1]) > 50)):
                        # Also check for patterns like 96.00.01.48 (with leading zeros)
                        if not any(o.startswith('0') and len(o) > 1 for o in octets):
                            filtered_matches.append(ip)
                
                if filtered_matches:
                    findings[category] = list(set(filtered_matches))[:20]
            else:
                findings[category] = list(set(matches))[:20]  # Limit to 20 unique matches
    
    # Scan SQL injection patterns
    for category, pattern in SQL_INJECTION_PATTERNS.items():
        matches = []
        for s in strings:
            found = re.findall(pattern, s, re.IGNORECASE)
            if found:
                matches.append(s)  # Include full string for context
        
        if matches:
            findings[f"SQL Injection - {category}"] = list(set(matches))[:15]
    
    return findings

def scan_for_keywords(strings):
    """Scan strings for suspicious keywords."""
    found_keywords = []
    
    for s in strings:
        s_lower = s.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in s_lower:
                found_keywords.append(s)
                break
    
    return list(set(found_keywords))[:30]  # Limit to 30 unique matches

def detect_shellcode(file_path):
    """Detect potential shellcode in binary file."""
    findings = {}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check for shellcode signatures (with higher thresholds to reduce false positives)
        signatures_found = []
        
        # NOP sled - only report if very long
        nop_sled = b'\x90' * 20
        if nop_sled in data:
            count = data.count(nop_sled)
            signatures_found.append(f"Long NOP Sled (20+ NOPs) (found {count} times)")
        
        # Syscalls - only in suspicious quantities
        syscall_x64_count = data.count(b'\x0f\x05')
        if syscall_x64_count > 200:  # Increased threshold
            signatures_found.append(f"Excessive x64 syscalls ({syscall_x64_count} times)")
        
        linux_syscall_count = data.count(b'\xcd\x80')
        if linux_syscall_count > 100:  # Increased threshold
            signatures_found.append(f"Excessive Linux syscalls ({linux_syscall_count} times)")
        
        # GetPC trick - common in position-independent shellcode, but also in legit code
        # Only report if combined with other indicators
        getpc_count = data.count(b'\xe8\x00\x00\x00\x00')
        suspicious_apis = any(api in data for api in [
            b'VirtualAlloc', b'VirtualProtect', b'CreateRemoteThread', 
            b'WriteProcessMemory', b'NtCreateThreadEx'
        ])
        
        if getpc_count > 50 and suspicious_apis:  # Only flag if both present
            signatures_found.append(f"GetPC trick with suspicious APIs ({getpc_count} times)")
        
        if signatures_found:
            findings['Shellcode Signatures'] = signatures_found
        
        # Check for shellcode-related APIs (filter out common legitimate ones)
        suspicious_apis_list = []
        api_patterns = [
            (b'VirtualAlloc', 'Memory allocation'),
            (b'VirtualProtect', 'Memory protection modification'),
            (b'CreateRemoteThread', 'Remote thread creation'),
            (b'WriteProcessMemory', 'Process memory writing'),
            (b'NtCreateThreadEx', 'Native thread creation'),
            (b'RtlCreateUserThread', 'User thread creation'),
        ]
        
        for api, description in api_patterns:
            if api in data:
                suspicious_apis_list.append(f"{api.decode('ascii')} ({description})")
        
        if suspicious_apis_list:
            findings['Suspicious Memory APIs'] = suspicious_apis_list
        
        # Detect high entropy sections (potential encrypted/obfuscated shellcode)
        entropy_sections = detect_high_entropy_sections(data, threshold=7.5)  # Increased threshold
        if entropy_sections:
            findings['Very High Entropy Sections'] = entropy_sections
        
        # Check for excessive executable opcodes (more strict threshold)
        opcode_density = calculate_opcode_density(data)
        if opcode_density > 0.6:  # Increased from 0.5 to 0.6
            findings['Very High Opcode Density'] = [f"{opcode_density:.2%} of file contains common x86 opcodes"]
        
    except Exception as e:
        print(f"Error during shellcode detection: {e}", file=sys.stderr)
    
    return findings

def detect_high_entropy_sections(data, chunk_size=256, threshold=7.0):
    """Detect sections with high entropy (potential encrypted shellcode)."""
    import math
    
    high_entropy_sections = []
    consecutive_high = 0
    first_high_offset = None
    
    for i in range(0, len(data) - chunk_size, chunk_size):
        chunk = data[i:i+chunk_size]
        
        # Calculate Shannon entropy
        if len(chunk) == 0:
            continue
            
        entropy = 0
        counter = Counter(chunk)
        for count in counter.values():
            p = count / len(chunk)
            entropy -= p * math.log2(p)
        
        if entropy >= threshold:
            if first_high_offset is None:
                first_high_offset = i
            consecutive_high += 1
        else:
            if consecutive_high >= 5:  # Only report if 5+ consecutive high-entropy chunks
                size_kb = (consecutive_high * chunk_size) / 1024
                high_entropy_sections.append(
                    f"Offset 0x{first_high_offset:08x}: {size_kb:.1f}KB of data with entropy >= {threshold:.1f}"
                )
            consecutive_high = 0
            first_high_offset = None
    
    # Check final section
    if consecutive_high >= 5:
        size_kb = (consecutive_high * chunk_size) / 1024
        high_entropy_sections.append(
            f"Offset 0x{first_high_offset:08x}: {size_kb:.1f}KB of data with entropy >= {threshold:.1f}"
        )
    
    return high_entropy_sections[:5]  # Limit to first 5

def calculate_opcode_density(data):
    """Calculate density of common x86 opcodes."""
    # Common x86/x64 opcodes
    common_opcodes = [
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  # PUSH
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,  # POP
        0x90,  # NOP
        0xC3,  # RET
        0xE8, 0xE9,  # CALL, JMP
        0xFF,  # Various (CALL, JMP indirect)
        0x8B, 0x89,  # MOV
        0x31, 0x33,  # XOR
        0x48, 0x4C,  # REX prefixes (x64)
    ]
    
    opcode_count = sum(1 for byte in data if byte in common_opcodes)
    return opcode_count / len(data) if len(data) > 0 else 0

def detect_privilege_escalation(file_path):
    """Detect privilege escalation techniques and indicators."""
    findings = {}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Filter out categories that commonly cause false positives
        filtered_patterns = {
            k: v for k, v in PRIVESC_PATTERNS.items() 
            if k not in ['Windows Service Abuse', 'DLL/SO Injection', 'Credential Access']
        }
        
        # For the filtered categories, check for patterns
        for category, patterns in filtered_patterns.items():
            matches = []
            for pattern in patterns:
                if pattern in data:
                    # Count occurrences
                    count = data.count(pattern)
                    
                    # Only flag if it appears multiple times or is particularly suspicious
                    if count >= 3 or category in ['Windows UAC Bypass', 'Linux Kernel Exploits']:
                        pattern_str = pattern.decode('ascii', errors='ignore')
                        matches.append(f"{pattern_str} ({count} occurrences)")
            
            if matches:
                findings[category] = matches[:10]  # Limit to 10 per category
        
        # Special handling for highly suspicious patterns
        highly_suspicious = {}
        
        # Check for token manipulation (strong indicator)
        token_privs = [b'SeDebugPrivilege', b'SeImpersonatePrivilege']
        token_matches = [p.decode('ascii') for p in token_privs if data.count(p) > 2]
        if token_matches:
            highly_suspicious['Token Privilege Manipulation'] = token_matches
        
        # Check for known UAC bypass techniques
        uac_bypasses = [b'eventvwr.exe', b'fodhelper.exe', b'sdclt.exe']
        uac_context = []
        for bypass in uac_bypasses:
            if bypass in data and b'mscfile' in data:  # Must have registry component too
                uac_context.append(bypass.decode('ascii') + ' with registry manipulation')
        if uac_context:
            highly_suspicious['UAC Bypass Techniques'] = uac_context
        
        # Merge highly suspicious findings
        findings.update(highly_suspicious)
        
    except Exception as e:
        print(f"Error during privilege escalation detection: {e}", file=sys.stderr)
    
    return findings

def calculate_file_hash(file_path, algorithm='sha256', buffer_size=8192):
    """
    Computes the hash of a file using the specified algorithm.

    Args:
        file_path (str): The path to the file.
        algorithm (str): The hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256').
        buffer_size (int): The size of chunks to read the file in (bytes).

    Returns:
        str: The hexadecimal hash digest of the file, or None if file not found.
    """
    # Create a hash object
    try:
        hash_func = hashlib.new(algorithm)
    except ValueError:
        print(f"Error: Invalid hash algorithm '{algorithm}'")
        return None

    # Open the file in binary mode for reading
    try:
        with open(file_path, 'rb') as f:
            # Read the file in chunks and update the hash object
            while chunk := f.read(buffer_size):
                hash_func.update(chunk)
        
        # Return the hexadecimal representation of the digest
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
        return None

def main():
    parser = argparse.ArgumentParser(
        description='Scan binary files for potentially suspicious strings'
    )
    parser.add_argument('file', help='Binary file to scan')
    parser.add_argument('-m', '--min-length', type=int, default=4,
                       help='Minimum string length (default: 4)')
    parser.add_argument('-e', '--encoding', choices=['ascii', 'unicode', 'both'],
                       default='both', help='String encoding to extract')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show all findings including potential false positives')
    parser.add_argument('--no-filter', action='store_true',
                       help='Disable false positive filtering (show everything)')
    
    args = parser.parse_args()
    
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File '{args.file}' not found", file=sys.stderr)
        sys.exit(1)
    
    print(f"Scanning: {file_path}")
    file_hash = calculate_file_hash(file_path)
    print(f"sha256 file hash: {file_hash}")
    print(f"File size: {file_path.stat().st_size:,} bytes")
    print("-" * 60)
    
    # Extract strings
    all_strings = []
    if args.encoding in ['ascii', 'both']:
        all_strings.extend(extract_strings(file_path, args.min_length, 'ascii'))
    if args.encoding in ['unicode', 'both']:
        all_strings.extend(extract_strings(file_path, args.min_length, 'unicode'))
    
    all_strings = list(set(all_strings))  # Remove duplicates
    print(f"Extracted {len(all_strings)} unique strings\n")
    
    # Scan for patterns
    pattern_findings = scan_for_patterns(all_strings)
    
    # Filter out certificate-related URLs unless verbose
    if not args.verbose and not args.no_filter and 'URLs' in pattern_findings:
        cert_keywords = ['pki', 'crl', 'ocsp', 'crt', 'cer', 'entrust', 'certificate']
        filtered_urls = [url for url in pattern_findings['URLs'] 
                        if not any(kw in url.lower() for kw in cert_keywords)]
        if filtered_urls:
            pattern_findings['URLs'] = filtered_urls
        else:
            del pattern_findings['URLs']
    
    # Filter out developer emails unless verbose
    if not args.verbose and not args.no_filter and 'Email Addresses' in pattern_findings:
        dev_domains = ['openssl.org', 'cryptsoft.com', 'caltech.edu', 'epfl.ch', 'gzip.org']
        filtered_emails = [email for email in pattern_findings['Email Addresses']
                          if not any(domain in email.lower() for domain in dev_domains)]
        if filtered_emails:
            pattern_findings['Email Addresses'] = filtered_emails
        else:
            del pattern_findings['Email Addresses']
    
    # Filter out build/source file paths unless verbose
    if not args.verbose and not args.no_filter and 'File Paths' in pattern_findings:
        build_indicators = ['\\src\\', '\\build\\', '\\openssl\\', '\\local\\', '\\dvs\\p4\\']
        filtered_paths = [path for path in pattern_findings['File Paths']
                         if not any(indicator in path.lower() for indicator in build_indicators)]
        if filtered_paths:
            pattern_findings['File Paths'] = filtered_paths
        else:
            del pattern_findings['File Paths']
    
    # Scan for keywords
    keyword_findings = scan_for_keywords(all_strings)
    
    # Detect shellcode
    print("Analyzing for shellcode patterns...")
    shellcode_findings = detect_shellcode(file_path)
    
    # Detect privilege escalation techniques
    print("Checking for privilege escalation indicators...")
    privesc_findings = detect_privilege_escalation(file_path)
    
    # Display results
    output_lines = []
    
    if pattern_findings:
        output_lines.append("=== SUSPICIOUS PATTERNS FOUND ===\n")
        for category, matches in pattern_findings.items():
            output_lines.append(f"\n{category} ({len(matches)} found):")
            for match in matches:
                output_lines.append(f"  - {match}")
    
    if keyword_findings:
        output_lines.append("\n\n=== SUSPICIOUS KEYWORDS FOUND ===\n")
        for finding in keyword_findings:
            output_lines.append(f"  - {finding}")
    
    if shellcode_findings:
        output_lines.append("\n\n=== SHELLCODE DETECTION ===\n")
        for category, matches in shellcode_findings.items():
            output_lines.append(f"\n{category}:")
            for match in matches:
                output_lines.append(f"  - {match}")
    
    if privesc_findings:
        output_lines.append("\n\n=== PRIVILEGE ESCALATION INDICATORS ===\n")
        for category, matches in privesc_findings.items():
            output_lines.append(f"\n{category} ({len(matches)} found):")
            for match in matches[:5]:  # Show max 5 per category in summary
                output_lines.append(f"  - {match}")
            if len(matches) > 5:
                output_lines.append(f"  ... and {len(matches) - 5} more")
    
    if not pattern_findings and not keyword_findings and not shellcode_findings and not privesc_findings:
        output_lines.append("No suspicious strings detected.")
    
    # Output results
    output_text = "\n".join(output_lines)
    print(output_text)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_text)
        print(f"\n\nResults saved to: {args.output}")

if __name__ == "__main__":
    main()
