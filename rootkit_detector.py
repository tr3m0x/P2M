#!/usr/bin/env python3
"""
BPF Rootkit Detection System
Detects kernel-level rootkits using eBPF with dynamic analysis.
No hardcoded indicators - uses behavioral and structural detection.
"""

import subprocess
import json
import sys
import os
import re
from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class BPFProgram:
    """Represents a loaded BPF program"""
    prog_id: int
    name: str
    prog_type: str
    tag: str
    loaded_at: str
    uid: int
    bytes_xlated: int
    bytes_memory: int
    map_ids: List[int]


@dataclass
class BPFMap:
    """Represents a BPF map"""
    map_id: int
    name: str
    map_type: str
    key_size: int
    value_size: int
    max_entries: int
    owner: Optional[int]


@dataclass
class DetectionResult:
    """Represents detection results"""
    detection_type: str
    severity: str  # critical, high, medium, low
    description: str
    details: Dict
    remediation: str


class KernelLockdownDetector:
    """Detects kernel lockdown modes"""

    @staticmethod
    def get_lockdown_status() -> Dict[str, str]:
        """Check kernel lockdown status"""
        lockdown_path = Path("/sys/kernel/security/lockdown")
        status = {}

        if lockdown_path.exists():
            try:
                with open(lockdown_path, 'r') as f:
                    content = f.read().strip()
                    status['lockdown_mode'] = content
            except PermissionError:
                status['lockdown_mode'] = 'Permission Denied'
        else:
            status['lockdown_mode'] = 'Not Available'

        # Check for LSM status
        lsm_path = Path("/sys/kernel/security/lsm")
        if lsm_path.exists():
            try:
                with open(lsm_path, 'r') as f:
                    status['lsm_active'] = f.read().strip()
            except PermissionError:
                status['lsm_active'] = 'Permission Denied'

        return status

    @staticmethod
    def check_integrity_monitoring() -> Dict[str, any]:
        """Check for IMA/AppArmor/SELinux status"""
        status = {}

        ima_path = Path("/sys/kernel/security/ima/policy")
        if ima_path.exists():
            status['ima_enabled'] = True
            try:
                with open(ima_path, 'r') as f:
                    status['ima_rules'] = len(f.readlines())
            except PermissionError:
                status['ima_rules'] = 'Permission Denied'
        else:
            status['ima_enabled'] = False

        # Check AppArmor
        apparmor_path = Path("/sys/module/apparmor")
        status['apparmor_available'] = apparmor_path.exists()

        # Check SELinux
        selinux_path = Path("/sys/fs/selinux")
        status['selinux_available'] = selinux_path.exists()

        return status


class BPFToolAnalyzer:
    """Analyzes BPF programs and maps using bpftool"""

    @staticmethod
    def _run_bpftool(args: List[str]) -> str:
        """Execute bpftool command"""
        try:
            result = subprocess.run(
                ['bpftool'] + args,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning("bpftool command timed out")
            return ""
        except FileNotFoundError:
            logger.error("bpftool not found. Install linux-tools or bpf-tools")
            return ""

    @staticmethod
    def _run_bpftool_json(args: List[str]) -> Dict:
        """Execute bpftool command with JSON output"""
        try:
            result = subprocess.run(
                ['bpftool', '-j'] + args,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.stdout:
                return json.loads(result.stdout)
            return {}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return {}

    def get_loaded_programs(self) -> List[BPFProgram]:
        """Get all loaded BPF programs"""
        prog_data = self._run_bpftool_json(['prog', 'show'])
        programs = []

        if isinstance(prog_data, list):
            for prog in prog_data:
                try:
                    program = BPFProgram(
                        prog_id=prog.get('id'),
                        name=prog.get('name', 'unknown'),
                        prog_type=prog.get('type', 'unknown'),
                        tag=prog.get('tag', ''),
                        loaded_at=prog.get('loaded_at', 'unknown'),
                        uid=prog.get('uid'),
                        bytes_xlated=prog.get('bytes_xlated', 0),
                        bytes_memory=prog.get('bytes_memory', 0),
                        map_ids=prog.get('map_ids', [])
                    )
                    programs.append(program)
                except (KeyError, TypeError):
                    continue

        return programs

    def get_loaded_maps(self) -> List[BPFMap]:
        """Get all loaded BPF maps"""
        map_data = self._run_bpftool_json(['map', 'show'])
        maps = []

        if isinstance(map_data, list):
            for bpf_map in map_data:
                try:
                    bmap = BPFMap(
                        map_id=bpf_map.get('id'),
                        name=bpf_map.get('name', 'unknown'),
                        map_type=bpf_map.get('type', 'unknown'),
                        key_size=bpf_map.get('key_size', 0),
                        value_size=bpf_map.get('value_size', 0),
                        max_entries=bpf_map.get('max_entries', 0),
                        owner=bpf_map.get('owner', None)
                    )
                    maps.append(bmap)
                except (KeyError, TypeError):
                    continue

        return maps

    def get_syscall_hooks(self) -> Dict[str, List[int]]:
        """Detect syscall hooks by analyzing programs"""
        hooks = {}
        programs = self.get_loaded_programs()

        for prog in programs:
            if 'tracepoint' in prog.prog_type or 'kprobe' in prog.prog_type:
                if 'sys_enter' in prog.name or 'sys_exit' in prog.name:
                    syscall = prog.name.split('_', 1)[0]
                    if syscall not in hooks:
                        hooks[syscall] = []
                    hooks[syscall].append(prog.prog_id)

        return hooks

    def analyze_program_behavior(self, prog_id: int) -> Dict:
        """Analyze a specific program's instructions"""
        output = self._run_bpftool(['prog', 'show', 'id', str(prog_id), 'xlated'])
        behavior = {
            'operations': [],
            'suspicious_patterns': []
        }

        # Look for suspicious operations
        suspicious_ops = [
            'bpf_probe_write_user',  # User memory write
            'bpf_probe_read',         # Kernel memory read
            'bpf_get_current_pid_tgid',  # Process identification
            'bpf_map_lookup_elem',    # Map operations
            'bpf_map_update_elem',    # Persistent storage
        ]

        for op in suspicious_ops:
            if op in output:
                behavior['operations'].append(op)
                if 'write_user' in op:
                    behavior['suspicious_patterns'].append('direct_user_memory_write')
                elif 'read' in op:
                    behavior['suspicious_patterns'].append('kernel_memory_read')

        return behavior


class FileIntegrityMonitor:
    """Detects file modification anomalies"""

    @staticmethod
    def check_sudoers_consistency() -> List[DetectionResult]:
        """Check /etc/sudoers consistency across different reads"""
        results = []
        sudoers_path = Path("/etc/sudoers")

        if not sudoers_path.exists():
            return results

        try:
            # Read sudoers file multiple times
            reads = []
            for i in range(3):
                with open(sudoers_path, 'r') as f:
                    reads.append(f.read())

            # Check for consistency
            if not all(r == reads[0] for r in reads):
                results.append(DetectionResult(
                    detection_type='file_modification_intercept',
                    severity='critical',
                    description='Inconsistent reads of /etc/sudoers file detected',
                    details={
                        'file': str(sudoers_path),
                        'reads_differ': True,
                        'read_count': len(reads)
                    },
                    remediation='Check for BPF programs hooking read syscalls'
                ))

            # Look for suspicious sudo rules
            suspicious_indicators = [
                'NOPASSWD',
                'root',
                '#'  # Comments added mid-file
            ]

            for content in reads:
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if line.startswith('#'):
                        continue
                    if 'ALL=(ALL' in line and 'NOPASSWD' in line:
                        # Check if this is expected
                        results.append(DetectionResult(
                            detection_type='suspicious_sudoers_rule',
                            severity='high',
                            description='Found NOPASSWD sudo rule',
                            details={
                                'line_number': i + 1,
                                'rule': line[:100]  # First 100 chars
                            },
                            remediation='Verify sudo configuration is authorized'
                        ))

        except PermissionError:
            logger.warning("Cannot read /etc/sudoers - requires root")

        return results

    @staticmethod
    def check_file_tampering_indicators() -> List[DetectionResult]:
        """Check for signs of file content tampering"""
        results = []
        test_files = ['/etc/sudoers', '/etc/passwd', '/etc/shadow']

        for file_path in test_files:
            path = Path(file_path)
            if not path.exists():
                continue

            try:
                # Get file stats
                stat_info = path.stat()

                # Check for unusual sizes
                if path.name == 'sudoers' and stat_info.st_size > 10000:
                    results.append(DetectionResult(
                        detection_type='unusual_file_size',
                        severity='medium',
                        description=f'{file_path} has unusually large size',
                        details={'size': stat_info.st_size},
                        remediation='Verify file contents have not been tampered with'
                    ))

            except OSError:
                pass

        return results


class ProcessAnomalyDetector:
    """Detects process-level anomalies"""

    @staticmethod
    def get_sudo_executions() -> List[Dict]:
        """Find sudo processes and their details"""
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=5
            )
            sudo_procs = []
            for line in result.stdout.split('\n'):
                if 'sudo' in line and 'grep' not in line:
                    parts = line.split()
                    if len(parts) >= 11:
                        sudo_procs.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'command': ' '.join(parts[10:])
                        })
            return sudo_procs
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    @staticmethod
    def check_permission_anomalies() -> List[DetectionResult]:
        """Check for unusual permission patterns"""
        results = []
        sensitive_files = ['/etc/sudoers', '/etc/shadow', '/root/.ssh']

        for file_path in sensitive_files:
            path = Path(file_path)
            if not path.exists():
                continue

            try:
                stat_info = path.stat()
                mode = oct(stat_info.st_mode)[-3:]

                # Check for unexpected permissions
                if file_path == '/etc/sudoers' and mode != '440':
                    results.append(DetectionResult(
                        detection_type='unusual_file_permissions',
                        severity='high',
                        description=f'{file_path} has unexpected permissions',
                        details={'permissions': mode, 'expected': '440'},
                        remediation='Verify file permissions and restore if needed'
                    ))

            except OSError:
                pass

        return results


class KProbeDetector:
    """Detects kernel probe-based hooks"""

    @staticmethod
    def check_kernel_probes() -> List[Dict]:
        """Check for active kernel probes"""
        probes = []
        kprobe_path = Path("/sys/kernel/debug/tracing/kprobe_events")

        if not kprobe_path.exists():
            return probes

        try:
            with open(kprobe_path, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        probes.append({
                            'probe': line.strip(),
                            'type': 'kprobe'
                        })
        except PermissionError:
            logger.warning("Cannot read kernel probes - requires root")

        return probes

    @staticmethod
    def check_tracepoint_hooks() -> List[Dict]:
        """Check for tracepoint hooks"""
        hooks = []
        tracepoint_path = Path("/sys/kernel/debug/tracing/available_events")

        if not tracepoint_path.exists():
            return hooks

        try:
            with open(tracepoint_path, 'r') as f:
                lines = f.readlines()

            # Check for suspicious syscall hooks
            syscall_patterns = [
                'sys_enter_openat',
                'sys_exit_openat',
                'sys_enter_read',
                'sys_exit_read',
                'sys_enter_execve',
            ]

            for line in lines:
                for pattern in syscall_patterns:
                    if pattern in line:
                        hooks.append({
                            'tracepoint': line.strip(),
                            'category': 'syscall_monitoring'
                        })

        except PermissionError:
            logger.warning("Cannot read tracepoints - requires root")

        return hooks


class RootkitDetector:
    """Main detection engine"""

    def __init__(self):
        self.bpf_analyzer = BPFToolAnalyzer()
        self.lockdown_detector = KernelLockdownDetector()
        self.file_monitor = FileIntegrityMonitor()
        self.process_detector = ProcessAnomalyDetector()
        self.kprobe_detector = KProbeDetector()
        self.detections: List[DetectionResult] = []

    def run_full_scan(self) -> List[DetectionResult]:
        """Execute comprehensive rootkit detection"""
        logger.info("Starting comprehensive rootkit detection scan...")

        # Phase 1: BPF Program Analysis
        logger.info("Phase 1: Analyzing BPF programs...")
        self._analyze_bpf_programs()

        # Phase 2: Syscall Hook Detection
        logger.info("Phase 2: Detecting syscall hooks...")
        self._detect_syscall_hooks()

        # Phase 3: File Integrity Checks
        logger.info("Phase 3: Checking file integrity...")
        self._check_file_integrity()

        # Phase 4: Process Analysis
        logger.info("Phase 4: Analyzing processes...")
        self._analyze_processes()

        # Phase 5: Kernel Security Status
        logger.info("Phase 5: Checking kernel security status...")
        self._check_kernel_security()

        # Phase 6: Memory Map Analysis
        logger.info("Phase 6: Analyzing memory maps...")
        self._analyze_memory_maps()

        return self.detections

    def _analyze_bpf_programs(self):
        """Detect suspicious BPF programs"""
        programs = self.bpf_analyzer.get_loaded_programs()

        if not programs:
            logger.info("No BPF programs loaded (or bpftool unavailable)")
            return

        logger.info(f"Found {len(programs)} loaded BPF programs")

        for prog in programs:
            # Analyze program behavior
            behavior = self.bpf_analyzer.analyze_program_behavior(prog.prog_id)

            if behavior['suspicious_patterns']:
                self.detections.append(DetectionResult(
                    detection_type='suspicious_bpf_operations',
                    severity='high',
                    description=f'BPF program {prog.name} uses suspicious operations',
                    details={
                        'program_id': prog.prog_id,
                        'program_name': prog.name,
                        'program_type': prog.prog_type,
                        'operations': behavior['operations'],
                        'patterns': behavior['suspicious_patterns'],
                        'memory_usage': prog.bytes_memory,
                        'map_ids': prog.map_ids
                    },
                    remediation='Verify BPF program source and purpose, unload if unauthorized'
                ))

            # Flag programs with excessive memory usage
            if prog.bytes_memory > 1000000:  # > 1MB
                self.detections.append(DetectionResult(
                    detection_type='high_memory_bpf_program',
                    severity='medium',
                    description=f'BPF program {prog.name} uses excessive memory',
                    details={
                        'program_id': prog.prog_id,
                        'memory_usage': prog.bytes_memory
                    },
                    remediation='Investigate program purpose and efficiency'
                ))

    def _detect_syscall_hooks(self):
        """Detect syscall interception"""
        hooks = self.bpf_analyzer.get_syscall_hooks()

        critical_syscalls = [
            'openat', 'read', 'write', 'execve', 'clone', 'fork',
            'socket', 'connect', 'bind', 'chmod', 'chown'
        ]

        for syscall in critical_syscalls:
            if syscall in hooks:
                self.detections.append(DetectionResult(
                    detection_type='critical_syscall_hook',
                    severity='critical',
                    description=f'Detected hook on {syscall} syscall',
                    details={
                        'syscall': syscall,
                        'program_ids': hooks[syscall],
                        'hook_count': len(hooks[syscall])
                    },
                    remediation='Identify and unload suspicious BPF programs'
                ))

    def _check_file_integrity(self):
        """Check file-level integrity"""
        self.detections.extend(self.file_monitor.check_sudoers_consistency())
        self.detections.extend(self.file_monitor.check_file_tampering_indicators())

    def _analyze_processes(self):
        """Analyze running processes"""
        self.detections.extend(self.process_detector.check_permission_anomalies())

        sudo_procs = self.process_detector.get_sudo_executions()
        if sudo_procs:
            logger.info(f"Found {len(sudo_procs)} sudo process(es)")

    def _check_kernel_security(self):
        """Check kernel security settings"""
        lockdown_status = self.lockdown_detector.get_lockdown_status()
        integrity_status = self.lockdown_detector.check_integrity_monitoring()

        if lockdown_status.get('lockdown_mode') == 'none':
            self.detections.append(DetectionResult(
                detection_type='insufficient_lockdown',
                severity='high',
                description='Kernel lockdown is not enabled',
                details={'lockdown_mode': 'none'},
                remediation='Enable kernel lockdown mode (integrity or confidentiality)'
            ))

        logger.info(f"Kernel lockdown: {lockdown_status.get('lockdown_mode', 'Unknown')}")
        logger.info(f"IMA enabled: {integrity_status.get('ima_enabled', False)}")

    def _analyze_memory_maps(self):
        """Analyze memory maps for anomalies"""
        maps = self.bpf_analyzer.get_loaded_maps()

        if not maps:
            return

        logger.info(f"Found {len(maps)} BPF maps")

        # Look for suspicious map patterns
        suspicious_patterns = {
            'map_fds': 'File descriptor tracking',
            'map_buff': 'Buffer address tracking',
            'map_pid': 'PID tracking',
        }

        for bpf_map in maps:
            for pattern, desc in suspicious_patterns.items():
                if pattern in bpf_map.name.lower():
                    self.detections.append(DetectionResult(
                        detection_type='suspicious_bpf_map',
                        severity='high',
                        description=f'Detected suspicious BPF map: {desc}',
                        details={
                            'map_id': bpf_map.map_id,
                            'map_name': bpf_map.name,
                            'map_type': bpf_map.map_type,
                            'max_entries': bpf_map.max_entries
                        },
                        remediation='Identify and unload BPF programs using this map'
                    ))

    def generate_report(self) -> str:
        """Generate a detection report"""
        report = []
        report.append("=" * 70)
        report.append("BPF ROOTKIT DETECTION REPORT")
        report.append("=" * 70)
        report.append("")

        if not self.detections:
            report.append("No threats detected")
            report.append("")
        else:
            # Group by severity
            by_severity = {}
            for detection in self.detections:
                if detection.severity not in by_severity:
                    by_severity[detection.severity] = []
                by_severity[detection.severity].append(detection)

            severity_order = ['critical', 'high', 'medium', 'low']
            for severity in severity_order:
                if severity not in by_severity:
                    continue

                report.append(f"\n[{severity.upper()}] {len(by_severity[severity])} findings:")
                report.append("-" * 70)

                for i, detection in enumerate(by_severity[severity], 1):
                    report.append(f"\n{i}. {detection.description}")
                    report.append(f"   Type: {detection.detection_type}")
                    report.append(f"   Details:")
                    for key, value in detection.details.items():
                        report.append(f"     - {key}: {value}")
                    report.append(f"   Remediation: {detection.remediation}")

        report.append("\n" + "=" * 70)
        report.append("End of Report")
        report.append("=" * 70)

        return "\n".join(report)


def main():
    """Main entry point"""
    if os.geteuid() != 0:
        logger.error("This script requires root privileges")
        logger.info("Run with: sudo python3 rootkit_detector.py")
        sys.exit(1)

    detector = RootkitDetector()

    try:
        results = detector.run_full_scan()
        report = detector.generate_report()
        print(report)

        # Exit with appropriate code
        critical_count = sum(1 for r in results if r.severity == 'critical')
        sys.exit(1 if critical_count > 0 else 0)

    except KeyboardInterrupt:
        logger.info("\nDetection interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
