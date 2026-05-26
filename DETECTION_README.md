# BPF Rootkit Detection System

Professional Python-based detection framework for kernel-level eBPF rootkits using dynamic analysis and behavioral detection.

## Overview

This detection system identifies BPF-based rootkits through multiple detection vectors:

1. **BPF Program Analysis** - Detects loaded BPF programs and suspicious operations
2. **Syscall Hook Detection** - Identifies hooks on critical system calls
3. **File Integrity Monitoring** - Detects file content tampering and inconsistencies
4. **Process Anomaly Detection** - Analyzes process-level indicators
5. **Kernel Security Status** - Verifies lockdown modes and security policies
6. **Memory Map Analysis** - Detects suspicious BPF data structures

## Key Features

- **No Hardcoded Indicators** - Dynamic detection based on behavioral patterns
- **Comprehensive Logging** - Clear audit trail of all detection phases
- **Professional Output** - Detailed reports with severity levels and remediation
- **Forensic Capabilities** - Deep analysis tools for incident investigation
- **Multi-Level Detection** - Catches rootkits through multiple independent channels

## Requirements

### System Requirements
- Linux kernel 5.8+ (for eBPF support)
- root/sudo access
- Python 3.6+

### Tools Required
```bash
# Install required tools on Debian/Ubuntu
sudo apt-get install -y linux-tools-generic bpf-tools strace lsof

# Or on Fedora/RHEL
sudo dnf install -y bpf-tools strace lsof
```

### Python Dependencies
No external Python packages required - uses only standard library and subprocess.

## Installation

```bash
# Clone repository or download files
cd P2M

# Make scripts executable
chmod +x rootkit_detector.py forensic_analyzer.py
```

## Usage

### Basic Detection Scan

```bash
# Run full detection scan
sudo python3 rootkit_detector.py
```

This performs:
1. BPF program enumeration
2. Syscall hook detection
3. File integrity checks
4. Process analysis
5. Kernel security verification
6. Memory map analysis

**Output**: Structured report with findings grouped by severity (critical, high, medium, low)

### Forensic Analysis

The forensic analyzer tool provides deep investigation capabilities:

#### List suspicious kernel modules
```bash
sudo python3 forensic_analyzer.py --modules
```

#### Analyze BPF memory usage
```bash
sudo python3 forensic_analyzer.py --memory
```

#### Dump program bytecode
```bash
sudo python3 forensic_analyzer.py --bytecode <PROG_ID>
```

Example:
```bash
bpftool prog show      # List programs and get IDs
sudo python3 forensic_analyzer.py --bytecode 5
```

#### Inspect BPF map contents
```bash
sudo python3 forensic_analyzer.py --inspect-map <MAP_ID>
```

#### Trace system calls
```bash
sudo python3 forensic_analyzer.py --trace-syscalls "sudo cat /etc/sudoers"
```

#### Generate full forensic report
```bash
sudo python3 forensic_analyzer.py --report
# Output saved to /tmp/bpf_forensics.json
```

## Detection Techniques

### 1. BPF Program Analysis

Analyzes each loaded BPF program for:
- Presence of `bpf_probe_write_user()` - Kernel-to-user memory writes
- Presence of `bpf_probe_read()` - Kernel memory access
- Presence of `bpf_map_*()` functions - Persistent data storage
- Excessive memory usage (> 1MB)
- Unusual program names or tags

### 2. Syscall Hook Detection

Identifies hooks on critical syscalls:
- `openat` - File opening
- `read` - File reading
- `write` - File writing
- `execve` - Process execution
- `clone`/`fork` - Process creation
- `chmod`/`chown` - Permission changes

### 3. File Integrity Monitoring

Tests for:
- **Read consistency** - Multiple reads of sensitive files returning different data
- **Anomalous permissions** - Unexpected file mode bits
- **Suspicious sudoers rules** - Unauthorized NOPASSWD entries
- **File size anomalies** - Files significantly larger than expected

### 4. Process-Level Detection

Checks for:
- Unusual sudo rule configurations
- Permission mismatches on sensitive files
- Anomalous process execution patterns

### 5. Kernel Security Status

Verifies:
- **Lockdown mode** - Integrity or confidentiality settings
- **LSM frameworks** - AppArmor, SELinux, SMACK status
- **IMA** - Integrity Measurement Architecture
- **Capability restrictions** - Process capability management

### 6. Memory Map Analysis

Identifies suspicious BPF maps:
- Maps tracking file descriptors (`map_fd*`)
- Maps tracking buffer addresses (`map_buff*`)
- Maps tracking process IDs (`map_pid*`)
- Unusually large map allocations

## Output Format

### Detection Report Structure

```
[CRITICAL] N findings:
  1. Detection description
     Type: detection_type
     Details:
       - field1: value1
       - field2: value2
     Remediation: recommended_action

[HIGH] N findings:
  ...

[MEDIUM] N findings:
  ...

[LOW] N findings:
  ...
```

### Exit Codes

- `0` - No critical findings
- `1` - Critical findings detected
- `130` - Interrupted by user

## Rootkit Detection Example

When TSUKUYOMI BPF rootkit is loaded, the detector identifies:

```
[CRITICAL] 1 findings:
  1. Detected hook on openat syscall
     Type: critical_syscall_hook
     Details:
       - syscall: openat
       - program_ids: [7]
       - hook_count: 1
     Remediation: Identify and unload suspicious BPF programs

[CRITICAL] 1 findings:
  1. Detected hook on read syscall
     Type: critical_syscall_hook
     Details:
       - syscall: read
       - program_ids: [7]
       - hook_count: 1
     Remediation: Identify and unload suspicious BPF programs

[HIGH] 2 findings:
  1. BPF program sudoadd uses suspicious operations
     Type: suspicious_bpf_operations
     Details:
       - program_id: 7
       - program_name: sudoadd
       - program_type: tracepoint
       - operations: ['bpf_probe_write_user', 'bpf_probe_read', 'bpf_map_lookup_elem', 'bpf_map_update_elem']
       - patterns: ['direct_user_memory_write', 'kernel_memory_read']
     Remediation: Verify BPF program source and purpose, unload if unauthorized

  2. Detected suspicious BPF map: File descriptor tracking
     Type: suspicious_bpf_map
     Details:
       - map_id: 8
       - map_name: map_fds
       - map_type: hash
       - max_entries: 8192
     Remediation: Identify and unload BPF programs using this map
```

## Remediation Steps

### If Rootkit Detected

1. **Immediate containment**
   ```bash
   # Document evidence
   sudo bpftool prog show > /tmp/bpf_programs.txt
   sudo bpftool map show > /tmp/bpf_maps.txt
   ```

2. **Unload malicious BPF program**
   ```bash
   # Identify program ID from detection report
   sudo bpftool prog show     # Find the program ID
   
   # Unload from BPF filesystem
   sudo rm -rf /sys/fs/bpf/<program_name>
   ```

3. **Verify file integrity**
   ```bash
   # Check sudoers file
   sudo visudo    # Will validate syntax
   
   # Restore from backup if compromised
   sudo cp /etc/sudoers.d/backup /etc/sudoers
   ```

4. **System restart** (recommended)
   ```bash
   sudo shutdown -r now
   ```

## Advanced Usage

### Continuous Monitoring

```bash
#!/bin/bash
# Monitor every 5 minutes
while true; do
    sudo python3 rootkit_detector.py >> /var/log/rootkit_monitor.log
    sleep 300
done
```

### Integration with SIEM

```bash
# Parse JSON forensic output for SIEM ingestion
sudo python3 forensic_analyzer.py --report | python3 -m json.tool
```

### Baseline Comparison

```bash
# Establish baseline
sudo python3 forensic_analyzer.py --report > /tmp/baseline.json

# Later comparison
sudo python3 forensic_analyzer.py --report > /tmp/current.json
diff /tmp/baseline.json /tmp/current.json
```

## Performance Considerations

- **Scan duration**: 5-30 seconds (depends on system load)
- **Memory usage**: ~50-100MB
- **CPU impact**: Minimal (mostly I/O bound)
- **Safe to run repeatedly**: Yes

## Limitations

1. Requires root access for full detection
2. Requires `bpftool` (may not be available on all distributions)
3. Some detection methods require kernel features (5.8+)
4. Cannot detect BPF rootkits that have already unloaded themselves

## Bypasses and Evasion

The detection system is robust against:
- Renamed BPF programs - Uses structural analysis
- Hidden maps - Enumerates via bpftool
- Polymorphic patterns - Detects behavioral signatures

Note: A sophisticated attacker could:
- Use userspace BPF loaders that hide from bpftool
- Modify bpftool itself
- Disable kernel trace mechanisms

Consider these as supplementary defenses:
- Kernel lockdown mode (CRITICAL)
- LSM frameworks (AppArmor, SELinux)
- IMA/EVM
- Mandatory access controls
- Regular security audits

## Architecture

### Detection Pipeline

```
Input Phase
  ↓
BPF Program Collection → Behavioral Analysis → Threat Scoring
  ↓
Syscall Hook Detection → Critical Syscall Analysis → Alert Generation
  ↓
File Integrity Checks → Consistency Testing → Anomaly Report
  ↓
Process Analysis → Permission Checks → Issue Logging
  ↓
Kernel Security Status → Policy Verification → Recommendations
  ↓
Memory Map Analysis → Structural Pattern Matching → Finding Aggregation
  ↓
Output Phase (Formatted Report)
```

### Design Principles

1. **Fail-safe** - Missing tools don't prevent other detections
2. **Non-intrusive** - Read-only analysis, no system modification
3. **Comprehensive** - Multiple independent detection channels
4. **Actionable** - Each finding includes remediation guidance
5. **Auditable** - Complete logging of detection process

## Security Considerations

### Running the Detector

- Ensure no malicious Python interpreter
- Run from trusted filesystem
- Verify tool integrity (bpftool, strace, lsof)
- Audit output for suspicious findings

### Preventing Rootkit Installation

```bash
# Enable kernel lockdown
echo "integrity" | sudo tee /sys/kernel/security/lockdown

# Enable AppArmor (if available)
sudo systemctl start apparmor

# Enable IMA
# (requires kernel config and bootloader parameters)
```

## Troubleshooting

### bpftool not found
```bash
# Install on Ubuntu/Debian
sudo apt-get install linux-tools-`uname -r`

# Install on Fedora/RHEL
sudo dnf install bpf-tools
```

### Permission Denied errors
```bash
# Some operations require full root
sudo python3 rootkit_detector.py

# Not sufficient: this won't work
python3 rootkit_detector.py   # Error!
```

### No BPF programs shown
```bash
# Normal if no BPF programs are loaded
# Check with bpftool directly
bpftool prog show
```

## Contributing

To enhance detection capabilities:

1. Add new detection classes in `rootkit_detector.py`
2. Implement `DetectionResult` for new findings
3. Test against known rootkits
4. Update documentation

## References

- [BPF and XDP Reference Guide](https://docs.kernel.org/bpf/)
- [eBPF Internals](https://www.kernel.org/doc/html/latest/bpf/)
- [bpftool Documentation](https://github.com/libbpf/bpftool)
- [Kernel Security Hardening](https://docs.kernel.org/admin-guide/kernel-security.html)

## License

This detection framework is provided for security research and system administration purposes.

## Disclaimer

This tool is provided as-is for defensive security purposes. The authors are not responsible for misuse or damage caused by this tool. Always obtain proper authorization before performing security assessments.
