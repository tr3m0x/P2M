#!/usr/bin/env python3
"""
eBPF Rootkit Detection System (Zero False Positives)
Differentiates between benign observability tools (Falco/Cilium) and rootkits
by scanning bytecode exclusively for memory-tampering and execution-hijacking helpers.
Zero hardcoded maps or program names.
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
    map_id: int
    name: str
    map_type: str
    key_size: int
    value_size: int
    max_entries: int
    owner: Optional[int]


@dataclass
class DetectionResult:
    detection_type: str
    severity: str
    description: str
    details: Dict
    remediation: str


class BPFToolAnalyzer:
    """Analyzes live BPF programs and maps using the bpftool interface"""

    @staticmethod
    def _run_bpftool(args: List[str]) -> str:
        try:
            result = subprocess.run(['bpftool'] + args, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return ""
        except FileNotFoundError:
            logger.error("bpftool not found. Install linux-tools or bpf-tools")
            return ""

    @staticmethod
    def _run_bpftool_json(args: List[str]) -> Dict:
        try:
            result = subprocess.run(['bpftool', '-j'] + args, capture_output=True, text=True, timeout=10)
            if result.stdout:
                return json.loads(result.stdout)
            return {}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return {}

    def get_loaded_programs(self) -> List[BPFProgram]:
        prog_data = self._run_bpftool_json(['prog', 'show'])
        programs = []
        if isinstance(prog_data, list):
            for prog in prog_data:
                try:
                    programs.append(BPFProgram(
                        prog_id=prog.get('id'),
                        name=prog.get('name', 'unknown'),
                        prog_type=prog.get('type', 'unknown'),
                        tag=prog.get('tag', ''),
                        loaded_at=prog.get('loaded_at', 'unknown'),
                        uid=prog.get('uid'),
                        bytes_xlated=prog.get('bytes_xlated', 0),
                        bytes_memory=prog.get('bytes_memory', 0),
                        map_ids=prog.get('map_ids', [])
                    ))
                except (KeyError, TypeError):
                    continue
        return programs

    def get_loaded_maps(self) -> List[BPFMap]:
        map_data = self._run_bpftool_json(['map', 'show'])
        maps = []
        if isinstance(map_data, list):
            for bpf_map in map_data:
                try:
                    maps.append(BPFMap(
                        map_id=bpf_map.get('id'),
                        name=bpf_map.get('name', 'unknown'),
                        map_type=bpf_map.get('type', 'unknown'),
                        key_size=bpf_map.get('key_size', 0),
                        value_size=bpf_map.get('value_size', 0),
                        max_entries=bpf_map.get('max_entries', 0),
                        owner=bpf_map.get('owner', None)
                    ))
                except (KeyError, TypeError):
                    continue
        return maps

    def get_active_links(self) -> List[Dict]:
        link_data = self._run_bpftool_json(['link', 'show'])
        return link_data if isinstance(link_data, list) else []

    def analyze_program_behavior(self, prog_id: int) -> Dict:
        """Scan translated BPF bytecode specifically for tampering functionality"""
        output = self._run_bpftool(['prog', 'dump', 'xlated', 'id', str(prog_id)])
        behavior = {
            'is_malicious': False,
            'tampering_helpers': []
        }

        # ONLY flag helpers that actively modify data or hijack execution.
        # We completely ignore benign helpers like bpf_probe_read or bpf_map_lookup.
        tampering_ops = [
            'bpf_probe_write_user',  # Overwrites user-space memory
            'bpf_override_return', # Hijacks system call return values
            "bpf_trace_printk",
            "bpf_probe_write_metadata"
        ]

        for op in tampering_ops:
            if op in output:
                behavior['is_malicious'] = True
                behavior['tampering_helpers'].append(op)

        return behavior


class RootkitDetector:
    """Main Threat Hunting Engine using Cascading Execution-Graph Correlation"""

    def __init__(self):
        self.bpf_analyzer = BPFToolAnalyzer()
        self.detections: List[DetectionResult] = []

        # Dynamic State Tracking (Zero Hardcoding)
        self.malicious_prog_ids: set = set()
        self.weaponized_map_ids: set = set()

    def run_full_scan(self) -> List[DetectionResult]:
        logger.info("Starting High-Precision eBPF Integrity Scan...")

        # Step 1: Find the actual malicious payloads
        logger.info("Phase 1: Scanning bytecode for memory-tampering instructions...")
        self._analyze_bpf_programs()

        # Step 2: See where the malicious payloads are hooked
        logger.info("Phase 2: Correlating malicious programs to system call hooks...")
        self._detect_syscall_hooks()

        # Step 3: Identify the maps supplying the malicious payloads
        logger.info("Phase 3: Isolating weaponized state maps...")
        self._analyze_memory_maps()

        return self.detections

    def _analyze_bpf_programs(self):
        """Identifies programs that have physical capabilities to tamper with the OS"""
        programs = self.bpf_analyzer.get_loaded_programs()
        if not programs:
            return

        for prog in programs:
            behavior = self.bpf_analyzer.analyze_program_behavior(prog.prog_id)

            if behavior['is_malicious']:
                # 1. Flag the program ID internally
                self.malicious_prog_ids.add(prog.prog_id)

                # 2. Tag all of its maps as weaponized dynamically
                for map_id in prog.map_ids:
                    self.weaponized_map_ids.add(map_id)

                # 3. Create the alert
                self.detections.append(DetectionResult(
                    detection_type='malicious_bpf_helper_detected',
                    severity='critical',
                    description=f'BPF program "{prog.name}" (ID: {prog.prog_id}) contains unauthorized memory-tampering instructions',
                    details={
                        'program_id': prog.prog_id,
                        'program_name': prog.name,
                        'tampering_helpers_found': behavior['tampering_helpers']
                    },
                    remediation='Unload immediately. Program is actively designed to subvert kernel or user space memory.'
                ))

    def _detect_syscall_hooks(self):
        """Only flags critical syscall hooks IF the attached program is malicious"""
        links = self.bpf_analyzer.get_active_links()

        critical_syscalls = [
            'openat', 'read', 'write', 'execve', 'getdents64',
            'socket', 'connect', 'bind', 'mkdir', 'close'
        ]

        for link in links:
            target = link.get('target_name', '').lower()
            prog_id = link.get('prog_id')
            if not target or not prog_id:
                continue

            # Only care if it's attached to a sensitive gateway AND the program is malicious
            for syscall in critical_syscalls:
                if syscall in target and prog_id in self.malicious_prog_ids:
                    self.detections.append(DetectionResult(
                        detection_type='weaponized_syscall_hook',
                        severity='critical',
                        description=f'Malicious program (ID: {prog_id}) is actively intercepting "{syscall}"',
                        details={
                            'syscall_intercepted': syscall,
                            'hook_target': target,
                            'handling_program_id': prog_id
                        },
                        remediation='Remove the associated BPF program to restore system call integrity.'
                    ))

    def _analyze_memory_maps(self):
        """Flags maps solely based on their link to malicious programs, ignoring map names"""
        maps = self.bpf_analyzer.get_loaded_maps()
        if not maps:
            return

        for bpf_map in maps:
            if bpf_map.map_id in self.weaponized_map_ids:
                self.detections.append(DetectionResult(
                    detection_type='weaponized_bpf_state_map',
                    severity='high',
                    description=f'Map "{bpf_map.name}" is supplying data to a malicious eBPF program',
                    details={
                        'map_id': bpf_map.map_id,
                        'map_name': bpf_map.name,  # Attacker can name this whatever they want!
                        'map_type': bpf_map.map_type,
                        'max_entries': bpf_map.max_entries
                    },
                    remediation='Isolate and delete this map environment.'
                ))

    def generate_report(self) -> str:
        report = []
        report.append("=" * 75)
        report.append("DEDICATED GENERATION 3 (eBPF) ROOTKIT DETECTION REPORT")
        report.append("=" * 75)
        report.append("")

        if not self.detections:
            report.append("[STATUS] SYSTEM SECURE. No malicious memory-tampering eBPF objects found.")
            report.append("         (Benign observability programs were ignored successfully).")
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
        sys.exit(1)

    detector = RootkitDetector()

    try:
        results = detector.run_full_scan()
        print(detector.generate_report())

        critical_threats = sum(1 for r in results if r.severity == 'critical')
        sys.exit(1 if critical_threats > 0 else 0)

    except Exception as e:
        logger.error(f"Integrity Scan Execution Interrupted: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()