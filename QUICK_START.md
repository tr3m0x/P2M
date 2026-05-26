# Quick Start Guide - BPF Rootkit Detection

## Installation & Setup

```bash
# Navigate to workspace
cd /home/p2m/Desktop/P2M

# Make scripts executable
chmod +x rootkit_detector.py forensic_analyzer.py testing_suite.py

# Install required tools (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y linux-tools-generic bpf-tools strace lsof

# Or on Fedora/RHEL
sudo dnf install -y bpf-tools strace lsof
```

## Basic Usage

### 1. Quick Detection Scan
```bash
# Run full detection scan (15-30 seconds)
sudo python3 rootkit_detector.py

# Output: Structured report with findings grouped by severity
```

### 2. Test Detection System
```bash
# Verify detection system is working
sudo python3 testing_suite.py

# Output: Test report showing all capabilities
```

### 3. Forensic Analysis
```bash
# Generate full forensic report
sudo python3 forensic_analyzer.py --report

# Output: JSON file at /tmp/bpf_forensics.json
cat /tmp/bpf_forensics.json
```

## Detecting TSUKUYOMI Rootkit

### When Rootkit IS Loaded

1. **Load the rootkit** (from TSUKUYOMI directory):
```bash
cd TSUKUYOMI
sudo bash load.sh
```

2. **Run detection**:
```bash
sudo python3 rootkit_detector.py
```

3. **Expected output**:
   - CRITICAL: Syscall hooks on `openat` and `read`
   - HIGH: Suspicious BPF program operations
   - HIGH: Suspicious BPF maps for tracking FDs and buffers

### When Rootkit IS NOT Loaded

1. **Verify not loaded**:
```bash
bpftool prog show | grep sudoadd  # Should be empty
```

2. **Run detection**:
```bash
sudo python3 rootkit_detector.py
```

3. **Expected output**:
   - No critical findings (or very minimal)
   - May show informational messages

## Detection Output Examples

### Finding: Critical Syscall Hook
```
[CRITICAL] 1 findings:
  1. Detected hook on read syscall
     Type: critical_syscall_hook
     Details:
       - syscall: read
       - program_ids: [7]
     Remediation: Identify and unload suspicious BPF programs
```

### Finding: Suspicious BPF Operations
```
[HIGH] 1 findings:
  1. BPF program sudoadd uses suspicious operations
     Type: suspicious_bpf_operations
     Details:
       - program_name: sudoadd
       - operations: ['bpf_probe_write_user', 'bpf_probe_read']
       - patterns: ['direct_user_memory_write']
```

## Remediation

### If Rootkit Detected

1. **Document evidence**:
```bash
sudo bpftool prog show > /tmp/evidence.txt
sudo bpftool map show >> /tmp/evidence.txt
```

2. **Unload rootkit**:
```bash
# Method 1: Remove BPF filesystem entry
sudo rm -rf /sys/fs/bpf/sudoadd

# Method 2: Using unload script
cd TSUKUYOMI
sudo bash unload.sh
```

3. **Verify removal**:
```bash
bpftool prog show | grep sudoadd  # Should be empty now
sudo python3 rootkit_detector.py   # Should show no critical findings
```

4. **Inspect damage**:
```bash
# Check /etc/sudoers for unauthorized entries
sudo visudo -c
sudo cat /etc/sudoers | grep -E "NOPASSWD|ALL="
```

## Advanced Usage

### View All Loaded Programs
```bash
bpftool prog show
```

### Inspect Specific Program
```bash
# Get program ID first
PROG_ID=7

# Dump bytecode
sudo python3 forensic_analyzer.py --bytecode $PROG_ID

# Dump JIT code
bpftool prog dump id $PROG_ID jited
```

### Monitor System Calls
```bash
# Trace sudo reading files
sudo python3 forensic_analyzer.py --trace-syscalls "sudo cat /etc/sudoers"
```

### Analyze Memory Usage
```bash
# Check BPF memory consumption
sudo python3 forensic_analyzer.py --memory
```

### Check Suspicious Modules
```bash
sudo python3 forensic_analyzer.py --modules
```

## Detection Techniques Used

1. **BPF Program Enumeration** - Lists all loaded BPF programs via bpftool
2. **Behavior Analysis** - Detects suspicious operations (memory writes, map usage)
3. **Syscall Hook Detection** - Identifies hooks on critical syscalls
4. **File Integrity** - Tests /etc/sudoers for tampering
5. **Memory Analysis** - Checks BPF map patterns and sizes
6. **Process Analysis** - Verifies file permissions and configurations
7. **Kernel Security** - Checks lockdown and LSM status

## Performance

- **Scan time**: 5-30 seconds
- **Memory usage**: 50-100MB
- **CPU impact**: Low (mostly I/O bound)
- **Safe to run**: Multiple times per day

## Troubleshooting

### Error: "bpftool not found"
```bash
# Install on Ubuntu/Debian
sudo apt-get install linux-tools-$(uname -r)

# Install on Fedora/RHEL
sudo dnf install bpf-tools
```

### Error: "Permission Denied"
```bash
# This script requires full root
sudo python3 rootkit_detector.py

# Sudo alone may not be sufficient
```

### No BPF programs shown
```bash
# This is normal if no programs are loaded
# Verify with:
bpftool prog show

# If bpftool shows programs but detector doesn't, 
# there may be a compatibility issue
```

### strace not available (optional)
```bash
# Forensic analyzer can work without it
sudo apt-get install strace
```

## Security Recommendations

### Enable Kernel Lockdown
```bash
# Check current status
cat /sys/kernel/security/lockdown

# Enable (requires root and may need kernel rebuild)
echo "integrity" | sudo tee /sys/kernel/security/lockdown
```

### Enable LSM Framework
```bash
# Check active LSMs
cat /sys/kernel/security/lsm

# AppArmor (if available)
sudo systemctl start apparmor
sudo systemctl enable apparmor
```

### Regular Monitoring
```bash
# Create cron job for periodic scanning
# Add to crontab:
0 */4 * * * /usr/bin/sudo /usr/bin/python3 /root/rootkit_detector.py >> /var/log/rootkit_check.log
```

## Integration Examples

### With Security Tools

```bash
# Export to SIEM
sudo python3 forensic_analyzer.py --report | jq '.' | \
  curl -X POST -H "Content-Type: application/json" \
  -d @- https://siem.example.com/api/events

# Log to syslog
sudo python3 rootkit_detector.py | \
  grep CRITICAL | logger -t rootkit-detector
```

### Continuous Monitoring
```bash
#!/bin/bash
# monitor.sh
while true; do
    OUTPUT=$(sudo python3 rootkit_detector.py 2>&1)
    CRITICAL_COUNT=$(echo "$OUTPUT" | grep -c CRITICAL)
    
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo "ALERT: Rootkit detected!" | mail -s "Rootkit Alert" admin@example.com
        echo "$OUTPUT" >> /var/log/rootkit_alerts.log
    fi
    
    sleep 3600  # Every hour
done
```

## Test Scenarios

### Test 1: Verify Detection Works
```bash
# Without rootkit loaded
sudo python3 testing_suite.py --scenario unloaded

# Should show: minimal or no critical findings
```

### Test 2: Test Against Running Rootkit
```bash
# Load rootkit
cd TSUKUYOMI && sudo bash load.sh

# Run detection
sudo python3 testing_suite.py --scenario loaded

# Should show: critical findings for syscall hooks
```

### Test 3: Full System Test
```bash
# Run complete test suite
sudo python3 testing_suite.py --full

# Shows component, functional, and scenario tests
```

## Files Overview

- **rootkit_detector.py** - Main detection engine (comprehensive analysis)
- **forensic_analyzer.py** - Advanced forensic analysis tools
- **testing_suite.py** - Validation and testing framework
- **DETECTION_README.md** - Complete documentation
- **QUICK_START.md** - This file

## Next Steps

1. **Initial scan**: `sudo python3 rootkit_detector.py`
2. **Test system**: `sudo python3 testing_suite.py`
3. **If findings**: Review DETECTION_README.md for remediation
4. **Setup monitoring**: Automate regular scans via cron
5. **Harden system**: Enable lockdown and LSM frameworks

## Support & Issues

### Common Issues

1. **False positives** - Legitimate BPF programs (e.g., bpf-based monitoring tools)
   - Verify program source before removing
   - Use forensic tools to analyze behavior

2. **Missing tools** - Some features optional
   - Script continues with reduced functionality
   - Install missing tools for full analysis

3. **Performance** - Slow detection on heavily loaded systems
   - Normal due to I/O limitations
   - Run during maintenance windows if needed

## Additional Resources

- BPF Documentation: https://docs.kernel.org/bpf/
- Kernel Hardening: https://wiki.ubuntu.com/SecurityTeam/KernelHardening
- bpftool Guide: https://github.com/libbpf/bpftool
- TSUKUYOMI Rootkit: https://github.com/chompie1337/TSUKUYOMI

---

**Last Updated**: 2024
**Maintained for**: System administrators and security professionals
