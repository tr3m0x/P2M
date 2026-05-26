#!/usr/bin/env python3
"""
BPF Rootkit Detection System (Gen 3 Focus)
Hyper-focused on detecting kernel-level rootkits utilizing the eBPF subsystem.
Uses behavioral, structural, and bytecode analysis to isolate malicious BPF objects.
"""

import subprocess
import json
import sys
import os
from dataclasses import dataclass
from typing import List, Dict, Optional
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
    """Represents a loaded BPF program inside the kernel"""
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
    """Represents a BPF map allocated in kernel space"""
    map_id: int
    name: str
    map_type: str
    key_size: int
    value_size: int
    max_entries: int
    owner: Optional[int]


@dataclass
class DetectionResult:
    """Represents eBPF specific detection results"""
    detection_type: str
    severity: str  # critical, high, medium, low
    description: str
    details: Dict
    remediation: str


class KernelLockdownDetector:
    """Detects kernel constraints regulating the BPF subsystem"""
    
    @staticmethod
    def get_lockdown_status() -> Dict[str, str]:
        """Check if kernel lockdown blocks arbitrary BPF program loading"""
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

        # Check for LSM status affecting eBPF
        lsm_path = Path("/sys/kernel/security/lsm")
        if lsm_path.exists():
            try:
                with open(lsm_path, 'r') as f:
                    status['lsm_active'] = f.read().strip()
            except PermissionError:
                status['lsm_active'] = 'Permission Denied'

        return status


class BPFToolAnalyzer:
    """Analyzes live BPF programs and maps using the bpftool interface"""

    @staticmethod
    def _run_bpftool(args: List[str]) -> str:
        """Execute bpftool command to fetch plaintext bytecode dumps"""
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
        """Execute bpftool command with JSON output for structured parsing"""
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
        """Get all loaded BPF programs from the kernel kernel structure"""
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
        """Get all loaded BPF maps allocated in memory"""
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
        """Identify BPF programs hooked directly onto system call traces"""
        hooks = {}
        programs = self.get_loaded_programs()

        for prog in programs:
            if 'tracepoint' in prog.prog_type or 'kprobe' in prog.prog_type:
                if 'sys_enter' in prog.name or 'sys_exit' in prog.name:
                    # Isolate the monitored syscall string pattern
                    parts = prog.name.split('_')
                    syscall = 'unknown'
                    for i, part in enumerate(parts):
                        if part in ['enter', 'exit'] and i + 1 < len(parts):
                            syscall = parts[i + 1]
                            break
                    if syscall == 'unknown' and len(parts) > 1:
                        syscall = parts[-1]

                    if syscall not in hooks:
                        hooks[syscall] = []
                    hooks[syscall].append(prog.prog_id)

        return hooks

    def analyze_program_behavior(self, prog_id: int) -> Dict:
        """Perform static analysis on translated BPF bytecode (xlated dump)"""
        output = self._run_bpftool(['prog', 'show', 'id', str(prog_id), 'xlated'])
        behavior = {
            'operations': [],
            'suspicious_patterns': []
        }

        # Look for powerful BPF Engine Helper Functions used for manipulation
        suspicious_ops = [
            'bpf_probe_write_user',      # Critical user-space memory modification
            'bpf_probe_read_user',       # Reading user space memory parameters
            'bpf_probe_read',            # Kernel memory read primitives
            'bpf_get_current_pid_tgid',  # Target process tracking/filtering
            'bpf_map_lookup_elem',       # State machine lookup
            'bpf_map_update_elem',       # Persistence optimization
        ]

        for op in suspicious_ops:
            if op in output:
                behavior['operations'].append(op)
                if 'write_user' in op:
                    behavior['suspicious_patterns'].append('direct_user_memory_write')
                elif 'read' in op:
                    behavior['suspicious_patterns'].append('kernel_or_user_memory_read')

        return behavior


class RootkitDetector:
    """Main Gen-3 BPF Threat Hunting Engine"""

    def __init__(self):
        self.bpf_analyzer = BPFToolAnalyzer()
        self.lockdown_detector = KernelLockdownDetector()
        self.detections: List[DetectionResult] = []

    def run_full_scan(self) -> List[DetectionResult]:
        """Execute focused eBPF verification pipeline"""
        logger.info("Starting targeted eBPF Subsystem Integrity Scan...")

        # Phase 1: Live Bytecode Verification & Helper Function Audit
        logger.info("Phase 1: Analyzing active BPF program objects...")
        self._analyze_bpf_programs()

        # Phase 2: Interception Point Audit (Syscall Mapping)
        logger.info("Phase 2: Verifying critical system call boundaries...")
        self._detect_syscall_hooks()

        # Phase 3: Structural Map Evaluation
        logger.info("Phase 3: Scanning allocated BPF memory maps...")
        self._analyze_memory_maps()

        # Phase 4: Host BPF Containment Auditing
        logger.info("Phase 4: Evaluating kernel eBPF isolation policy...")
        self._check_kernel_security()

        return self.detections

    def _analyze_bpf_programs(self):
        """Identify anomalous or unlinked BPF programs run by the kernel"""
        programs = self.bpf_analyzer.get_loaded_programs()

        if not programs:
            logger.info("No active BPF programs parsed or subsystem is empty.")
            return

        logger.info(f"Parsing {len(programs)} active kernel BPF objects...")

        for prog in programs:
            behavior = self.bpf_analyzer.analyze_program_behavior(prog.prog_id)

            if behavior['suspicious_patterns']:
                self.detections.append(DetectionResult(
                    detection_type='suspicious_bpf_bytecode_capabilities',
                    severity='high',
                    description=f'BPF program "{prog.name}" (ID: {prog.prog_id}) possesses hook manipulation helpers',
                    details={
                        'program_id': prog.prog_id,
                        'program_name': prog.name,
                        'program_type': prog.prog_type,
                        'helpers_found': behavior['operations'],
                        'behavioral_risk': behavior['suspicious_patterns'],
                        'memory_usage_bytes': prog.bytes_memory
                    },
                    remediation='Verify program origin via bpftool. Unload if bytecode source is unauthorized.'
                ))

            # Monitor excessive runtime allocation sizes
            if prog.bytes_memory > 1000000:
                self.detections.append(DetectionResult(
                    detection_type='excessive_bpf_memory_footprint',
                    severity='medium',
                    description=f'BPF program {prog.name} consumes an unusual kernel allocation memory size',
                    details={'program_id': prog.prog_id, 'memory_usage': prog.bytes_memory},
                    remediation='Investigate if the program contains excessive unrolled loops or logic trees.'
                ))

    def _detect_syscall_hooks(self):
        """Flag eBPF attachment anomalies on high-value system execution components"""
        hooks = self.bpf_analyzer.get_syscall_hooks()

        # Target targets mirrored by Gen 3 rootkits (e.g., directory hiding, credential padding)
        critical_syscalls = [
            'openat', 'read', 'write', 'execve', 'getdents64',
            'socket', 'connect', 'bind', 'mkdir'
        ]

        for syscall in critical_syscalls:
            if syscall in hooks:
                self.detections.append(DetectionResult(
                    detection_type='bpf_syscall_boundary_intercept',
                    severity='critical',
                    description=f'Active eBPF program intercepted the "{syscall}" system call gateway',
                    details={
                        'syscall_intercepted': syscall,
                        'handling_program_ids': hooks[syscall]
                    },
                    remediation='Analyze the program bytecode structure immediately using bpftool prog dump.'
                ))

    def _analyze_memory_maps(self):
        """Analyze memory maps for architectural filtering indicators"""
        maps = self.bpf_analyzer.get_loaded_maps()

        if not maps:
            return

        # Explicitly audits names tied to state management in evasion payloads
        suspicious_patterns = {
            'map_fds': 'File Descriptor tracking table',
            'map_buff': 'Buffer manipulation space',
            'map_pid': 'PID configuration mapping',
            'pid_hide': 'Process evasion structural map',
            'map_to_patch': 'Memory patch location lookup state'
        }

        for bpf_map in maps:
            for pattern, desc in suspicious_patterns.items():
                if pattern in bpf_map.name.lower():
                    self.detections.append(DetectionResult(
                        detection_type='anomalous_bpf_map_definition',
                        severity='high',
                        description=f'Detected structural BPF memory map designated for filtering: {desc}',
                        details={
                            'map_id': bpf_map.map_id,
                            'map_name': bpf_map.name,
                            'map_type': bpf_map.map_type,
                            'max_entries': bpf_map.max_entries
                        },
                        remediation='Identify the parent BPF program loading this map context and isolate it.'
                    ))

    def _check_kernel_security(self):
        """Check container isolation layers regulating raw BPF execution map accesses"""
        lockdown_status = self.lockdown_detector.get_lockdown_status()

        if lockdown_status.get('lockdown_mode') == 'none' or '[none]' in lockdown_status.get('lockdown_mode', ''):
            self.detections.append(DetectionResult(
                detection_type='unbounded_bpf_environment',
                severity='medium',
                description='Kernel Lockdown mechanism is disabled; BPF space can modify memory lines freely',
                details={'lockdown_mode': lockdown_status.get('lockdown_mode')},
                remediation='Enable kernel lockdown configuration rules to limit low-level writing tools.'
            ))

    def generate_report(self) -> str:
        """Compile an architectural technical audit overview summary"""
        report = []
        report.append("=" * 75)
        report.append("DEDICATED GENERATION 3 (eBPF) ROOTKIT DETECTION REPORT")
        report.append("=" * 75)
        report.append("")

        if not self.detections:
            report.append("[STATUS] No suspicious eBPF hooks or malicious memory states identified.")
            report.append("")
        else:
            by_severity = {}
            for detection in self.detections:
                if detection.severity not in by_severity:
                    by_severity[detection.severity] = []
                by_severity[detection.severity].append(detection)

            for severity in ['critical', 'high', 'medium', 'low']:
                if severity not in by_severity:
                    continue

                report.append(f"\n[{severity.upper()}] Verified eBPF Findings ({len(by_severity[severity])}):")
                report.append("-" * 75)

                for i, detection in enumerate(by_severity[severity], 1):
                    report.append(f"\n {i}. Threat: {detection.description}")
                    report.append(f"    Classification Type: {detection.detection_type}")
                    report.append(f"    Technical Context Parameters:")
                    for k, v in detection.details.items():
                        report.append(f"      * {k}: {v}")
                    report.append(f"    Remediation Strategy: {detection.remediation}")

        report.append("\n" + "=" * 75)
        return "\n".join(report)


def main():
    if os.geteuid() != 0:
        logger.error("Root elevation constraint failure. Script must interact directly with the BPF system.")
        logger.info("Execute utility using administrative context: sudo python3 rootkit_detector.py")
        sys.exit(1)

    detector = RootkitDetector()

    try:
        results = detector.run_full_scan()
        print(detector.generate_report())

        # Trigger anomalous termination code if critical hooks are validated
        critical_threats = sum(1 for r in results if r.severity == 'critical')
        sys.exit(1 if critical_threats > 0 else 0)

    except Exception as e:
        logger.error(f"Integrity Scan Execution Interrupted: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()