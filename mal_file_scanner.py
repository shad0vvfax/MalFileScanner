#!/usr/bin/env python3
"""
MalFileScanner - Comprehensive malware analysis tool for files and executables
Analyzes files for suspicious strings, patterns, and malicious indicators

Features:
- Multi-language base64 payload detection (PowerShell, PHP, JavaScript, Python, Bash)
- Shellcode and exploit detection
- Privilege escalation technique identification
- SSH key and configuration abuse detection
- SQL injection pattern recognition
- Packer and compiler identification
- File hashing (MD5, SHA1, SHA256)
- Detailed analysis reports

Useful for malware analysis, incident response, and security research
"""

import re
import sys
import argparse
import hashlib
import base64
from pathlib import Path
from collections import Counter
from datetime import datetime

# Common suspicious string patterns
SUSPICIOUS_PATTERNS = {
    'IP Addresses': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'URLs': r'https?://[^\s<>"{}|\\^`\[\]]+',
    'Email Addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'Registry Keys': r'HKEY_[A-Z_]+\\[^\x00]+',
    'File Paths': r'[A-Za-z]:\\(?:[^\x00\\/:*?"<>|\r\n]+\\)+[^\x00\\/:*?"<>|\r\n]+',
    'Shell Commands': r'(?:cmd\.exe|powershell\.exe|bash|sh)(?:\s+[-/][^\x00]+|\s+[A-Za-z0-9_]+\.(?:bat|ps1|sh|py))',
    'Suspicious Scripts': r'(?:wget|curl|invoke-webrequest|iwr|downloadstring|downloadfile)\s+http',
    'Malicious PowerShell Flags': r'powershell(?:\.exe)?\s+.*?(?:-(?:nop|noprofile|noninteractive|executionpolicy\s+bypass|ep\s+bypass|w(?:indowstyle)?\s+hidden|enc|encodedcommand|command|-)|/(?:nop|noprofile|ep\s+bypass|w\s+hidden|enc|command|-))',
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

# Suspicious keywords - Use specific phrases to reduce false positives
SUSPICIOUS_KEYWORDS = [
    # Malware types (specific variants)
    'keylogger', 'backdoor', 'ransomware', 'cryptolocker', 'cryptor', 'stealer', 
    'trojan.downloader', 'trojan-downloader', 'virus.', 'worm.', 'rootkit',
    
    # Post-exploitation tools
    'mimikatz', 'procdump', 'hashdump', 'secretsdump', 'lazagne',
    'invoke-mimikatz', 'invoke-bloodhound', 'powersploit', 'msfvenom',
    
    # Evasion techniques
    'bypass uac', 'bypass amsi', 'bypass defender', 'disable defender',
    'disable antivirus', 'kill av',
    
    # Remote access patterns
    'reverse_shell', 'bind_shell', 'reverse shell', 'bind shell',
    'php shell', 'web shell', 'webshell', 'shell_exec',
    'spawn shell', 'pop shell', '/bin/sh -i', '/bin/bash -i',
    
    # Attack frameworks
    'meterpreter', 'cobalt_strike', 'cobaltstrike', 'metasploit',
    'empire agent', 'sliver implant',
    
    # Privilege escalation (specific context)
    'privilege_escalation', 'privesc', 'priv esc', 'root exploit',
    'impersonate_token', 'impersonate token',
    
    # Credential theft (specific patterns)
    'dump_creds', 'steal_creds', 'credz', 'dump lsass',
    'steal password', 'password stealer', 'grab credentials',
    
    # Persistence mechanisms
    'add_persistence', 'install_backdoor', 'persistence_script',
    'add registry run', 'scheduled_task_backdoor',
    
    # Exploit/vulnerability specific
    '0day', 'zero-day', 'zero day', 'exploit-db', 'cve-exploit',
    'exploit kit', 'exploit_code',
    
    # Obfuscation/encoding (suspicious context)
    'base64_payload', 'encoded_payload', 'decrypt_payload',
    'xor_decrypt', 'decode_shellcode',
    
    # Leet speak / intentional obfuscation (as complete words)
    ' h4ck ', ' backd00r ', ' p4yl04d ', ' sh3ll ',
    ' cr4ck ', ' pwn3d ', ' r00t ', ' 1337 ',
    
    # Authentication bypass
    'bypass_auth', 'skip_auth', 'auth_bypass', 'sql_inject',
    
    # SSH abuse (specific)
    'authorized_keys backdoor', 'ssh_backdoor', 'ssh_persist',
]

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

# SSH-related suspicious patterns
SSH_PATTERNS = {
    'SSH Private Keys': [
        b'-----BEGIN RSA PRIVATE KEY-----',
        b'-----BEGIN DSA PRIVATE KEY-----',
        b'-----BEGIN EC PRIVATE KEY-----',
        b'-----BEGIN OPENSSH PRIVATE KEY-----',
        b'-----BEGIN PRIVATE KEY-----',
        b'-----BEGIN ENCRYPTED PRIVATE KEY-----'
    ],
    'SSH Commands': [
        b'ssh -o StrictHostKeyChecking=no',
        b'ssh -o UserKnownHostsFile=/dev/null',
        b'ssh -i /root/.ssh/',
        b'ssh -N -D',  # SOCKS proxy
        b'ssh -L',  # Local port forwarding
        b'ssh -R',  # Remote port forwarding
        b'ssh-keygen -f',
        b'chmod 600 ~/.ssh/',
        b'eval `ssh-agent',
        b'ssh-add -'
    ],
    'SSH Config Abuse': [
        b'~/.ssh/authorized_keys',
        b'/root/.ssh/authorized_keys',
        b'echo ssh-rsa',
        b'>> ~/.ssh/authorized_keys',
        b'PasswordAuthentication no',
        b'PubkeyAuthentication yes',
        b'PermitRootLogin yes',
        b'StrictHostKeyChecking no'
    ],
    'SSH Tunneling': [
        b'ProxyCommand',
        b'DynamicForward',
        b'LocalForward',
        b'RemoteForward',
        b'ProxyJump',
        b'-D 127.0.0.1:',
        b'-L 127.0.0.1:',
        b'-R 127.0.0.1:'
    ]
}

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
            # Filter IP addresses to remove OIDs and version numbers
            if category == 'IP Addresses':
                filtered_matches = []
                for ip in matches:
                    octets = ip.split('.')
                    try:
                        # Check if it looks like a real IP (not an OID or version number)
                        first = int(octets[0])
                        second = int(octets[1]) if len(octets) > 1 else 0
                        
                        # Filter out patterns that look like versions
                        if first in [0, 1, 2, 3, 4, 5, 6] and second == 0:
                            continue  # Likely a version number
                        
                        # Also check for leading zeros (not valid in IPs)
                        if any(o.startswith('0') and len(o) > 1 for o in octets):
                            continue
                        
                        # Keep localhost, private ranges, and IPs with reasonable values
                        if first in [10, 127, 172, 192] or first > 50:
                            filtered_matches.append(ip)
                    except (ValueError, IndexError):
                        continue
                
                if filtered_matches:
                    findings[category] = list(set(filtered_matches))[:20]
            
            # Filter URLs to remove format strings and malformed URLs
            elif category == 'URLs':
                filtered_urls = []
                for url in matches:
                    # Skip format strings
                    if '%s' in url or '%d' in url:
                        continue
                    # Skip malformed URLs
                    if url.startswith('https://https://') or url.startswith('http://http://'):
                        continue
                    # Skip if too short (likely fragments)
                    if len(url) < 15:
                        continue
                    # Clean up URLs with concatenated garbage
                    url = re.sub(r'[^a-zA-Z0-9/\-._~:?#\[\]@!$&\'()*+,;=%]+$', '', url)
                    # Skip W3C spec URLs and xmlns declarations
                    if 'w3.org' in url.lower() or 'xmlns' in url.lower():
                        continue
                    # Re-check length after cleaning
                    if len(url) >= 15:
                        filtered_urls.append(url)
                
                if filtered_urls:
                    findings[category] = list(set(filtered_urls))[:20]
            else:
                findings[category] = list(set(matches))[:20]
    
    # Scan SQL injection patterns
    for category, pattern in SQL_INJECTION_PATTERNS.items():
        matches = []
        for s in strings:
            found = re.findall(pattern, s, re.IGNORECASE)
            if found:
                matches.append(s)
        
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
    
    return list(set(found_keywords))[:30]

def detect_shellcode(file_path):
    """Detect potential shellcode in binary file."""
    findings = {}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        
        # Check for shellcode signatures
        signatures_found = []
        
        # NOP sled - only report if very long
        nop_sled = b'\x90' * 20
        if nop_sled in data:
            count = data.count(nop_sled)
            signatures_found.append(f"Long NOP Sled (20+ NOPs) (found {count} times)")
        
        # Syscalls - adjust thresholds based on file size
        syscall_x64_count = data.count(b'\x0f\x05')
        syscall_threshold = 500 if file_size > 5_000_000 else 200
        
        if syscall_x64_count > syscall_threshold:
            density = syscall_x64_count / (file_size / 1_000_000)
            if density > 200:
                signatures_found.append(f"Very high x64 syscall density ({syscall_x64_count} times, {density:.0f}/MB)")
        
        linux_syscall_count = data.count(b'\xcd\x80')
        if linux_syscall_count > 100:
            signatures_found.append(f"Excessive Linux syscalls ({linux_syscall_count} times)")
        
        # GetPC trick
        getpc_count = data.count(b'\xe8\x00\x00\x00\x00')
        suspicious_apis = any(api in data for api in [
            b'VirtualAlloc', b'VirtualProtect', b'CreateRemoteThread', 
            b'WriteProcessMemory', b'NtCreateThreadEx'
        ])
        
        if getpc_count > 50 and suspicious_apis:
            getpc_density = getpc_count / (file_size / 1_000_000)
            if getpc_density > 50:
                signatures_found.append(f"GetPC trick with suspicious APIs ({getpc_count} times, {getpc_density:.0f}/MB)")
        
        if signatures_found:
            findings['Shellcode Signatures'] = signatures_found
        
        # Check for shellcode-related APIs
        suspicious_apis_list = []
        api_patterns = [
            (b'VirtualAlloc', 'Memory allocation'),
            (b'VirtualProtect', 'Memory protection modification'),
            (b'CreateRemoteThread', 'Remote thread creation'),
            (b'WriteProcessMemory', 'Process memory writing'),
            (b'NtCreateThreadEx', 'Native thread creation'),
            (b'RtlCreateUserThread', 'User thread creation'),
        ]
        
        min_api_count = 4 if file_size > 5_000_000 else 3
        api_count = sum(1 for api, _ in api_patterns if api in data)
        
        if api_count >= min_api_count:
            for api, description in api_patterns:
                if api in data:
                    suspicious_apis_list.append(f"{api.decode('ascii')} ({description})")
        
        if suspicious_apis_list:
            findings['Suspicious Memory APIs'] = suspicious_apis_list
        
        # Detect high entropy sections
        entropy_sections = detect_high_entropy_sections(data, threshold=7.5)
        if entropy_sections:
            findings['Very High Entropy Sections'] = entropy_sections
        
        # Check for excessive executable opcodes
        opcode_density = calculate_opcode_density(data)
        if opcode_density > 0.6:
            findings['Very High Opcode Density'] = [f"{opcode_density:.2%} of file contains common x86 opcodes"]
        
    except Exception as e:
        print(f"Error during shellcode detection: {e}", file=sys.stderr)
    
    return findings

def detect_high_entropy_sections(data, chunk_size=256, threshold=7.0):
    """Detect sections with high entropy."""
    import math
    
    high_entropy_sections = []
    consecutive_high = 0
    first_high_offset = None
    
    for i in range(0, len(data) - chunk_size, chunk_size):
        chunk = data[i:i+chunk_size]
        
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
            if consecutive_high >= 5:
                size_kb = (consecutive_high * chunk_size) / 1024
                high_entropy_sections.append(
                    f"Offset 0x{first_high_offset:08x}: {size_kb:.1f}KB of data with entropy >= {threshold:.1f}"
                )
            consecutive_high = 0
            first_high_offset = None
    
    if consecutive_high >= 5:
        size_kb = (consecutive_high * chunk_size) / 1024
        high_entropy_sections.append(
            f"Offset 0x{first_high_offset:08x}: {size_kb:.1f}KB of data with entropy >= {threshold:.1f}"
        )
    
    return high_entropy_sections[:5]

def calculate_opcode_density(data):
    """Calculate density of common x86 opcodes."""
    common_opcodes = [
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  # PUSH
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,  # POP
        0x90,  # NOP
        0xC3,  # RET
        0xE8, 0xE9,  # CALL, JMP
        0xFF,  # Various
        0x8B, 0x89,  # MOV
        0x31, 0x33,  # XOR
        0x48, 0x4C,  # REX prefixes
    ]
    
    opcode_count = sum(1 for byte in data if byte in common_opcodes)
    return opcode_count / len(data) if len(data) > 0 else 0

def detect_privilege_escalation(file_path):
    """Detect privilege escalation techniques and indicators."""
    findings = {}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        file_size = len(data)
        
        filtered_patterns = {
            k: v for k, v in PRIVESC_PATTERNS.items() 
            if k not in ['Windows Service Abuse', 'DLL/SO Injection', 'Credential Access']
        }
        
        for category, patterns in filtered_patterns.items():
            matches = []
            for pattern in patterns:
                if pattern in data:
                    count = data.count(pattern)
                    
                    if count >= 3 or category in ['Windows UAC Bypass', 'Linux Kernel Exploits']:
                        pattern_str = pattern.decode('ascii', errors='ignore')
                        matches.append(f"{pattern_str} ({count} occurrences)")
            
            if matches:
                findings[category] = matches[:10]
        
        highly_suspicious = {}
        
        token_privs = [b'SeDebugPrivilege', b'SeImpersonatePrivilege']
        token_matches = [p.decode('ascii') for p in token_privs if data.count(p) > 2]
        if token_matches:
            highly_suspicious['Token Privilege Manipulation'] = token_matches
        
        uac_bypasses = [b'eventvwr.exe', b'fodhelper.exe', b'sdclt.exe']
        uac_context = []
        for bypass in uac_bypasses:
            if bypass in data and b'mscfile' in data:
                uac_context.append(bypass.decode('ascii') + ' with registry manipulation')
        if uac_context:
            highly_suspicious['UAC Bypass Techniques'] = uac_context
        
        # Filter out ptrace in large binaries
        if 'Process Injection' in findings and file_size > 5_000_000:
            findings['Process Injection'] = [
                m for m in findings['Process Injection'] 
                if not m.startswith('ptrace')
            ]
            if not findings['Process Injection']:
                del findings['Process Injection']
        
        findings.update(highly_suspicious)
        
    except Exception as e:
        print(f"Error during privilege escalation detection: {e}", file=sys.stderr)
    
    return findings

def detect_ssh_patterns(file_path):
    """Detect SSH-related patterns."""
    findings = {}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        for category, patterns in SSH_PATTERNS.items():
            matches = []
            for pattern in patterns:
                if pattern in data:
                    count = data.count(pattern)
                    pattern_str = pattern.decode('ascii', errors='ignore')
                    matches.append(f"{pattern_str} [{count}x]")
            
            if matches:
                findings[category] = matches
        
    except Exception as e:
        print(f"Error during SSH pattern detection: {e}", file=sys.stderr)
    
    return findings

def detect_base64_payloads(strings):
    """Detect base64 encoded strings that might be payloads."""
    findings = {
        'Suspicious Base64 Strings': [],
        'Decoded Indicators': []
    }
    
    # Pattern for base64 strings (minimum 40 chars to reduce false positives)
    base64_pattern = re.compile(r'([A-Za-z0-9+/]{40,}={0,2})')
    
    # PowerShell encoded command pattern
    powershell_encoded = re.compile(
        r'powershell(?:\.exe)?\s+.*?(?:-e(?:nc(?:odedcommand)?)?|/e(?:nc(?:odedcommand)?)?)\s+([A-Za-z0-9+/=]{40,})',
        re.IGNORECASE
    )
    
    # PHP base64 decode patterns
    php_base64 = re.compile(
        r'(?:base64_decode|eval)\s*\(\s*["\']([A-Za-z0-9+/=]{40,})["\']',
        re.IGNORECASE
    )
    
    # JavaScript/Node.js base64 patterns
    js_base64 = re.compile(
        r'(?:atob|Buffer\.from)\s*\(\s*["\']([A-Za-z0-9+/=]{40,})["\']',
        re.IGNORECASE
    )
    
    # Python base64 patterns
    python_base64 = re.compile(
        r'(?:base64\.(?:b64decode|decode(?:string)?)|codecs\.decode)\s*\(\s*["\']([A-Za-z0-9+/=]{40,})["\']',
        re.IGNORECASE
    )
    
    # Bash/shell base64 patterns
    bash_base64 = re.compile(
        r'(?:base64\s+(?:-d|--decode)|echo\s+["\']([A-Za-z0-9+/=]{40,})["\'].*?\|\s*base64\s+-d)',
        re.IGNORECASE
    )
    
    # Generic pattern: base64 in eval/exec contexts
    eval_base64 = re.compile(
        r'(?:eval|exec|system|shell_exec|passthru|assert)\s*\(\s*["\']?(?:base64_decode|atob|Buffer\.from)?\s*\(?["\']([A-Za-z0-9+/=]{40,})',
        re.IGNORECASE
    )
    
    # PowerShell suspicious patterns to check in decoded content
    powershell_suspicious_patterns = [
        (r'-(?:nop|noprofile)', 'NoProfile flag'),
        (r'-(?:ep|executionpolicy)\s+(?:bypass|unrestricted)', 'Bypass execution policy'),
        (r'-(?:w|windowstyle)\s+hidden', 'Hidden window'),
        (r'-(?:noninteractive|noni)', 'Non-interactive mode'),
        (r'invoke-expression|iex', 'Invoke-Expression (code execution)'),
        (r'downloadstring|downloadfile', 'Download content'),
        (r'net\.webclient', '.NET WebClient (download)'),
        (r'invoke-webrequest|iwr', 'Invoke-WebRequest'),
        (r'start-process.*-windowstyle\s+hidden', 'Hidden process execution'),
        (r'invoke-mimikatz', 'Mimikatz (credential theft)'),
        (r'invoke-shellcode', 'Shellcode injection'),
        (r'invoke-command.*-scriptblock', 'Remote command execution'),
        (r'new-object\s+system\.net\.webclient', 'WebClient instantiation'),
        (r'bitstransfer', 'BITS transfer'),
        (r'convertto-securestring.*-asplaintext', 'Plaintext credential conversion'),
    ]
    
    suspicious_keywords = [
        b'powershell', b'cmd.exe', b'bash', b'sh -c', b'/bin/',
        b'http://', b'https://', b'wget', b'curl', b'invoke',
        b'download', b'exec', b'eval', b'system', b'shell',
        b'MZ', b'PE', b'\x4d\x5a',  # PE header
        b'#!/', b'<?php', b'<script',
        b'password', b'passwd', b'secret', b'key=',
        b'iex', b'invoke-expression', b'downloadstring', b'downloadfile',
        b'invoke-webrequest', b'net.webclient', b'bitstransfer',
        b'start-process', b'invoke-command', b'invoke-mimikatz',
        b'bypass', b'unrestricted', b'remotesigned',
    ]
    
    shellcode_patterns = [
        b'\x90\x90\x90',  # NOP sled
        b'\xeb\xfe',  # JMP short
        b'\xff\xe4',  # JMP ESP
        b'\x55\x89\xe5',  # Function prologue
    ]
    
    processed_base64 = set()  # Track already processed base64 strings
    
    def check_powershell_patterns(decoded_text):
        """Check decoded text for PowerShell suspicious patterns."""
        ps_indicators = []
        for pattern, description in powershell_suspicious_patterns:
            if re.search(pattern, decoded_text, re.IGNORECASE):
                ps_indicators.append(description)
        return ps_indicators
    
    def process_base64_match(b64_string, context_type, original_string=""):
        """Process a base64 match and add to findings."""
        if b64_string in processed_base64:
            return
        
        processed_base64.add(b64_string)
        
        try:
            decoded_bytes = base64.b64decode(b64_string)
            
            if len(decoded_bytes) < 10:
                return
            
            # Try different decodings
            decoded_text = None
            encoding_used = None
            
            # Try UTF-16LE first (PowerShell)
            try:
                decoded_text = decoded_bytes.decode('utf-16-le')
                encoding_used = 'UTF-16LE'
            except:
                # Try UTF-8
                try:
                    decoded_text = decoded_bytes.decode('utf-8')
                    encoding_used = 'UTF-8'
                except:
                    # Fallback to ASCII
                    try:
                        decoded_text = decoded_bytes.decode('ascii', errors='ignore')
                        encoding_used = 'ASCII'
                    except:
                        pass
            
            # Calculate entropy
            entropy = 0
            if len(decoded_bytes) > 0:
                counter = Counter(decoded_bytes)
                for count in counter.values():
                    p = count / len(decoded_bytes)
                    if p > 0:
                        import math
                        entropy -= p * math.log2(p)
            
            # Check for suspicious content
            is_suspicious = False
            found_indicators = [context_type]
            
            # Check keywords
            for keyword in suspicious_keywords:
                if keyword in decoded_bytes.lower():
                    is_suspicious = True
                    found_indicators.append(keyword.decode('ascii', errors='ignore'))
            
            # Check shellcode patterns
            for pattern in shellcode_patterns:
                if pattern in decoded_bytes:
                    is_suspicious = True
                    found_indicators.append('shellcode pattern')
                    break
            
            # Check for PE header
            if decoded_bytes[:2] == b'MZ':
                is_suspicious = True
                found_indicators.append('PE executable')
            
            # Check for high entropy
            if entropy > 7.0 and len(decoded_bytes) > 100:
                is_suspicious = True
                found_indicators.append(f'high entropy ({entropy:.2f})')
            
            # Check PowerShell patterns if we have decoded text
            if decoded_text:
                ps_indicators = check_powershell_patterns(decoded_text)
                if ps_indicators:
                    is_suspicious = True
                    found_indicators.extend(ps_indicators[:3])
            
            if is_suspicious or context_type != "Standalone":
                display_b64 = b64_string[:60] + '...' if len(b64_string) > 60 else b64_string
                
                # Create preview
                if decoded_text:
                    preview = decoded_text[:150] + '...' if len(decoded_text) > 150 else decoded_text
                else:
                    preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in decoded_bytes[:50])
                    if len(decoded_bytes) > 50:
                        preview += '...'
                
                findings['Suspicious Base64 Strings'].append(
                    f"{display_b64} ({len(decoded_bytes)} bytes decoded)"
                )
                
                if encoding_used:
                    found_indicators.insert(1, encoding_used)
                
                indicator_str = ', '.join(set(found_indicators))
                findings['Decoded Indicators'].append(
                    f"Indicators: {indicator_str} | Content: {preview}"
                )
        
        except Exception:
            pass
    
    # Check for PowerShell encoded commands
    for string in strings:
        ps_matches = powershell_encoded.findall(string)
        for ps_encoded in ps_matches:
            process_base64_match(ps_encoded, "PowerShell -EncodedCommand", string)
    
    # Check for PHP base64_decode
    for string in strings:
        php_matches = php_base64.findall(string)
        for php_b64 in php_matches:
            process_base64_match(php_b64, "PHP base64_decode/eval", string)
    
    # Check for JavaScript atob/Buffer.from
    for string in strings:
        js_matches = js_base64.findall(string)
        for js_b64 in js_matches:
            process_base64_match(js_b64, "JavaScript atob/Buffer.from", string)
    
    # Check for Python base64
    for string in strings:
        py_matches = python_base64.findall(string)
        for py_b64 in py_matches:
            process_base64_match(py_b64, "Python base64.b64decode", string)
    
    # Check for eval/exec with base64
    for string in strings:
        eval_matches = eval_base64.findall(string)
        for eval_b64 in eval_matches:
            process_base64_match(eval_b64, "eval/exec with base64", string)
    
    # Check for standalone base64 strings (not in a command context)
    for string in strings:
        matches = base64_pattern.findall(string)
        for match in matches:
            if len(match) >= 40 and match not in processed_base64:
                # Only process if it looks suspicious (contains certain patterns)
                try:
                    decoded = base64.b64decode(match, validate=True)
                    if len(decoded) >= 10:
                        # Quick check for suspicious content
                        has_suspicious = any(kw in decoded.lower() for kw in suspicious_keywords[:10])
                        has_binary = decoded[:2] == b'MZ' or b'\x90\x90\x90' in decoded
                        
                        if has_suspicious or has_binary:
                            process_base64_match(match, "Standalone", string)
                except:
                    pass
    
    # Remove empty categories
    if not findings['Suspicious Base64 Strings']:
        del findings['Suspicious Base64 Strings']
    if not findings['Decoded Indicators']:
        del findings['Decoded Indicators']
    
    # Limit results
    if 'Suspicious Base64 Strings' in findings:
        findings['Suspicious Base64 Strings'] = findings['Suspicious Base64 Strings'][:10]
    if 'Decoded Indicators' in findings:
        findings['Decoded Indicators'] = findings['Decoded Indicators'][:10]
    
    return findings

def calculate_file_hashes(file_path):
    """Calculate MD5, SHA1, and SHA256 hashes."""
    hashes = {}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        hashes['MD5'] = hashlib.md5(data).hexdigest()
        hashes['SHA1'] = hashlib.sha1(data).hexdigest()
        hashes['SHA256'] = hashlib.sha256(data).hexdigest()
        
    except Exception as e:
        print(f"Error calculating hashes: {e}", file=sys.stderr)
    
    return hashes

def get_file_metadata(file_path):
    """Get file metadata."""
    metadata = {}
    
    try:
        stat = file_path.stat()
        metadata['File Size'] = f"{stat.st_size:,} bytes ({stat.st_size / (1024*1024):.2f} MB)"
        metadata['Created'] = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        metadata['Modified'] = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        metadata['Accessed'] = datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')
        
    except Exception as e:
        print(f"Error getting metadata: {e}", file=sys.stderr)
    
    return metadata

def detect_packer_compiler(file_path):
    """Detect if file is packed or identify compiler/language."""
    info = {
        'File Type': 'Unknown',
        'Compiler/Language': [],
        'Packer/Protector': [],
        'Signatures': []
    }
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check PE file
        if data[:2] == b'MZ':
            info['File Type'] = 'PE (Windows Executable)'
        # Check ELF file
        elif data[:4] == b'\x7fELF':
            info['File Type'] = 'ELF (Linux/Unix Executable)'
        # Check Mach-O file
        elif data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            info['File Type'] = 'Mach-O (macOS Executable)'
        
        # Detect compilers and languages
        compiler_signatures = {
            'Microsoft Visual C++': [b'Microsoft (R) C/C++', b'Microsoft Visual C++', b'MSVC'],
            'GCC': [b'GCC: (', b'GCC:', b'gcc version'],
            'Clang': [b'clang version', b'LLVM'],
            'MinGW': [b'MinGW', b'mingw'],
            'Borland': [b'Borland C++', b'Turbo C++'],
            'Intel C++ Compiler': [b'Intel(R) C++'],
            'Go': [b'Go build ID:', b'go.buildid', b'runtime.main', b'type..hash', b'go.itab'],
            'Rust': [b'rustc version', b'.rust_eh_personality', b'_ZN4core', b'std::panicking'],
            'Python': [b'Py_Initialize', b'PyEval_', b'python3', b'libpython'],
            'C#/.NET': [b'mscoree.dll', b'mscorlib', b'.NET Framework', b'System.Reflection'],
            'Java': [b'java/lang/', b'META-INF/MANIFEST.MF'],
            'Delphi': [b'Borland Delphi', b'@Borland'],
            'AutoIt': [b'AU3!', b'AutoIt v3 Script'],
            'Nim': [b'NimMain', b'Nim Runtime'],
        }
        
        for compiler, signatures in compiler_signatures.items():
            for sig in signatures:
                if sig in data:
                    if compiler not in info['Compiler/Language']:
                        info['Compiler/Language'].append(compiler)
                    break
        
        # Detect packers and protectors
        packer_signatures = {
            'UPX': [b'UPX!', b'UPX0', b'UPX1', b'UPX2'],
            'ASPack': [b'ASPack', b'.aspack', b'.adata'],
            'PECompact': [b'PECompact', b'PEC2'],
            'Themida': [b'Themida', b'Oreans', b'.themida'],
            'VMProtect': [b'VMProtect', b'.vmp0', b'.vmp1'],
            'Enigma Protector': [b'Enigma Protector', b'.enigma1', b'.enigma2'],
            'ASProtect': [b'ASProtect', b'.aspr'],
            'Armadillo': [b'Armadillo', b'Silicon Realms'],
            'Obsidium': [b'Obsidium', b'.obsidium'],
            'MPRESS': [b'MPRESS', b'.MPRESS'],
            'PEtite': [b'PEtite', b'.petite'],
            'NSPack': [b'NSPack', b'.nsp0', b'.nsp1'],
            'ExeStealth': [b'ExeStealth', b'WebtoolMaster'],
            'NeoLite': [b'NeoLite', b'NeoLite32'],
            'WWPack32': [b'WWPack32', b'WWPACK'],
            'Molebox': [b'MoleBox', b'.molebox'],
            'PE-Armor': [b'PE-Armor', b'PE Armor'],
            'Yoda Protector': [b"Yoda's Protector", b'YodaProtector'],
            'Packman': [b'PACKMAN'],
            'RLPack': [b'RLPack', b'.packed'],
            'MEW': [b'MEW ', b'MEW11'],
            'FSG': [b'FSG!', b'FSG '],
            'Petite': [b'petite', b'.petite'],
            'NsPack': [b'NsPack', b'.nsp'],
            'PE-Pack': [b'PE-PACK'],
            'tElock': [b'tElock', b'.tElock'],
            'Crinkler': [b'Crinkler', b'CRINKLER'],
            '.NET Reactor': [b'.NET Reactor', b'Eziriz'],
            'ConfuserEx': [b'ConfuserEx', b'Confuser'],
            'SmartAssembly': [b'SmartAssembly', b'.smarrt'],
        }
        
        for packer, signatures in packer_signatures.items():
            for sig in signatures:
                if sig in data:
                    if packer not in info['Packer/Protector']:
                        info['Packer/Protector'].append(packer)
                    break
        
        # Additional heuristics for packed files
        if not info['Packer/Protector']:
            suspicious_sections = [
                b'.upx', b'.aspack', b'.adata', b'.packed', b'.protect',
                b'.vmp', b'.enigma', b'.themida', b'UPX0', b'UPX1'
            ]
            
            found_suspicious = []
            for section in suspicious_sections:
                if section in data:
                    section_name = section.decode('ascii', errors='ignore')
                    if section_name not in found_suspicious:
                        found_suspicious.append(section_name)
            
            if found_suspicious:
                info['Signatures'].append(f"Suspicious section names: {', '.join(found_suspicious)}")
            
            # Calculate overall entropy
            if len(data) > 1000:
                import math
                entropy = 0
                counter = Counter(data[:10000])
                for count in counter.values():
                    p = count / 10000
                    entropy -= p * math.log2(p) if p > 0 else 0
                
                if entropy > 7.2:
                    info['Signatures'].append(f"High entropy detected ({entropy:.2f}/8.0) - possible packing/encryption")
        
    except Exception as e:
        print(f"Error detecting packer/compiler: {e}", file=sys.stderr)
    
    return info

def main():
    parser = argparse.ArgumentParser(
        description='MalFileScanner - Comprehensive malware analysis tool for files and executables',
        epilog='Examples:\n'
               '  %(prog)s malware.exe\n'
               '  %(prog)s suspicious.ps1 -o report.txt\n'
               '  %(prog)s webshell.php -v --no-filter\n',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('file', help='File to scan (binary, script, or text)')
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
    
    # Show scanning progress
    print("=" * 60)
    print("MALFILESCANNER v1.0")
    print("=" * 60)
    print(f"Target: {file_path.name}")
    
    print("\n[*] Calculating file hashes...")
    hashes = calculate_file_hashes(file_path)
    
    print("[*] Detecting packer/compiler...")
    packer_info = detect_packer_compiler(file_path)
    
    print("[*] Getting file metadata...")
    metadata = get_file_metadata(file_path)
    
    print("\n" + "=" * 60)
    print("SCANNING FOR SUSPICIOUS PATTERNS")
    print("=" * 60)
    
    # Extract strings
    all_strings = []
    if args.encoding in ['ascii', 'both']:
        all_strings.extend(extract_strings(file_path, args.min_length, 'ascii'))
    if args.encoding in ['unicode', 'both']:
        all_strings.extend(extract_strings(file_path, args.min_length, 'unicode'))
    
    all_strings = list(set(all_strings))
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
    print("[*] Analyzing for shellcode patterns...")
    shellcode_findings = detect_shellcode(file_path)
    
    # Detect privilege escalation techniques
    print("[*] Checking for privilege escalation indicators...")
    privesc_findings = detect_privilege_escalation(file_path)
    
    # Detect SSH patterns
    print("[*] Checking for SSH-related patterns...")
    ssh_findings = detect_ssh_patterns(file_path)
    
    # Detect base64 encoded payloads
    print("[*] Analyzing base64 encoded strings...")
    base64_findings = detect_base64_payloads(all_strings)
    
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    
    # Build output
    output_lines = []
    
    # Add header with file info
    output_lines.append("=" * 60)
    output_lines.append("FILE ANALYSIS REPORT")
    output_lines.append("=" * 60)
    output_lines.append(f"\nFile: {file_path.name}")
    output_lines.append(f"Path: {file_path.absolute()}")
    output_lines.append(f"\nFile Size: {metadata.get('File Size', 'Unknown')}")
    output_lines.append(f"Created:  {metadata.get('Created', 'Unknown')}")
    output_lines.append(f"Modified: {metadata.get('Modified', 'Unknown')}")
    output_lines.append(f"Accessed: {metadata.get('Accessed', 'Unknown')}")
    output_lines.append(f"\nMD5:    {hashes.get('MD5', 'N/A')}")
    output_lines.append(f"SHA1:   {hashes.get('SHA1', 'N/A')}")
    output_lines.append(f"SHA256: {hashes.get('SHA256', 'N/A')}")
    
    # Add packer/compiler information
    output_lines.append(f"\nFile Type: {packer_info['File Type']}")
    
    if packer_info['Compiler/Language']:
        output_lines.append(f"Compiler/Language: {', '.join(packer_info['Compiler/Language'])}")
    else:
        output_lines.append("Compiler/Language: Not detected")
    
    if packer_info['Packer/Protector']:
        output_lines.append(f"⚠ Packer/Protector: {', '.join(packer_info['Packer/Protector'])}")
    else:
        output_lines.append("Packer/Protector: None detected")
    
    if packer_info['Signatures']:
        output_lines.append("\nAdditional Signatures:")
        for sig in packer_info['Signatures']:
            output_lines.append(f"  • {sig}")
    
    output_lines.append(f"\nStrings Extracted: {len(all_strings)}")
    output_lines.append("\n" + "=" * 60)
    output_lines.append("FINDINGS")
    output_lines.append("=" * 60)
    
    # Display results
    has_findings = False
    
    if pattern_findings:
        output_lines.append("\n=== SUSPICIOUS PATTERNS FOUND ===\n")
        has_findings = True
        for category, matches in pattern_findings.items():
            output_lines.append(f"\n{category} ({len(matches)} found):")
            for match in matches:
                output_lines.append(f"  - {match}")
    
    if keyword_findings:
        output_lines.append("\n\n=== SUSPICIOUS KEYWORDS FOUND ===\n")
        has_findings = True
        for finding in keyword_findings:
            output_lines.append(f"  - {finding}")
    
    if shellcode_findings:
        output_lines.append("\n\n=== SHELLCODE DETECTION ===\n")
        has_findings = True
        for category, matches in shellcode_findings.items():
            output_lines.append(f"\n{category}:")
            for match in matches:
                output_lines.append(f"  - {match}")
    
    if privesc_findings:
        output_lines.append("\n\n=== PRIVILEGE ESCALATION INDICATORS ===\n")
        has_findings = True
        for category, matches in privesc_findings.items():
            output_lines.append(f"\n{category} ({len(matches)} found):")
            for match in matches[:5]:
                output_lines.append(f"  - {match}")
            if len(matches) > 5:
                output_lines.append(f"  ... and {len(matches) - 5} more")
    
    if ssh_findings:
        output_lines.append("\n\n=== SSH-RELATED PATTERNS ===\n")
        has_findings = True
        for category, matches in ssh_findings.items():
            output_lines.append(f"\n{category} ({len(matches)} found):")
            for match in matches:
                output_lines.append(f"  - {match}")
    
    if base64_findings:
        output_lines.append("\n\n=== BASE64 ENCODED PAYLOADS ===\n")
        has_findings = True
        for category, matches in base64_findings.items():
            output_lines.append(f"\n{category}:")
            for i, match in enumerate(matches):
                output_lines.append(f"  [{i+1}] {match}")
    
    if not has_findings:
        output_lines.append("\n✓ No suspicious patterns detected.")
    
    # Output results
    output_text = "\n".join(output_lines)
    print("\n" + output_text)
    
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output_text)
            print(f"\n{'=' * 60}")
            print(f"✓ Full report (with hashes) saved to: {args.output}")
            print("=" * 60)
        except Exception as e:
            print(f"\nError saving report: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
