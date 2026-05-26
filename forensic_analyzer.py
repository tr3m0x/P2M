#!/usr/bin/env python3
"""
Advanced BPF Rootkit Analysis Tool
Provides detailed forensic analysis capabilities for kernel-level threats.
"""

import subprocess
import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class BPFForensics:
    """Advanced forensic analysis of BPF programs"""

    @staticmethod
    def dump_program_bytecode(prog_id: int) -> str:
        """Extract and display program bytecode"""
        try:
            result = subprocess.run(
                ['bpftool', 'prog', 'dump', 'id', str(prog_id), 'xlated'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    @staticmethod
    def dump_program_jit(prog_id: int) -> str:
        """Extract JIT-compiled code"""
        try:
            result = subprocess.run(
                ['bpftool', 'prog', 'dump', 'id', str(prog_id), 'jited'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    @staticmethod
    def inspect_map_contents(map_id: int, limit: int = 10) -> List[Dict]:
        """Inspect BPF map contents"""
        entries = []
        try:
            result = subprocess.run(
                ['bpftool', 'map', 'dump', 'id', str(map_id)],
                capture_output=True,
                text=True,
                timeout=10
            )

            lines = result.stdout.split('\n')
            for i, line in enumerate(lines[:limit]):
                if line.strip():
                    entries.append({
                        'entry': i,
                        'data': line.strip()
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return entries

    @staticmethod
    def trace_program_execution(prog_id: int, duration: int = 5) -> str:
        """Trace program execution statistics"""
        try:
            result = subprocess.run(
                ['bpftool', 'prog', 'stat'],
                capture_output=True,
                text=True,
                timeout=duration + 5
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    @staticmethod
    def check_program_verifier() -> Dict:
        """Check BPF verifier logs"""
        verifier_info = {
            'total_programs': 0,
            'verified_safely': 0,
            'suspicious_programs': []
        }

        try:
            result = subprocess.run(
                ['bpftool', 'prog', 'show', '-j'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.stdout:
                programs = json.loads(result.stdout)
                if isinstance(programs, list):
                    verifier_info['total_programs'] = len(programs)

        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

        return verifier_info


class SystemCallTracer:
    """Trace system call patterns for anomalies"""

    @staticmethod
    def trace_syscalls(command: str, syscalls: Optional[List[str]] = None) -> Dict:
        """Trace syscalls made by a command"""
        trace_data = {
            'command': command,
            'syscalls_traced': [],
            'suspicious_calls': []
        }

        if syscalls is None:
            syscalls = ['openat', 'read', 'write', 'mmap', 'mprotect']

        syscall_filter = ','.join(syscalls)

        try:
            result = subprocess.run(
                ['strace', '-e', syscall_filter, '-o', '/tmp/strace.log', command],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Read strace output
            log_path = Path('/tmp/strace.log')
            if log_path.exists():
                with open(log_path, 'r') as f:
                    lines = f.readlines()
                    trace_data['syscalls_traced'] = [line.strip() for line in lines[:50]]

                log_path.unlink()

        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("strace not available or command failed")

        return trace_data

    @staticmethod
    def monitor_file_descriptor_leaks() -> Dict:
        """Monitor for file descriptor anomalies"""
        fd_data = {
            'processes': [],
            'anomalies': []
        }

        try:
            result = subprocess.run(
                ['lsof', '-n', '-P'],
                capture_output=True,
                text=True,
                timeout=10
            )

            lines = result.stdout.split('\n')
            for line in lines[1:]:  # Skip header
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) >= 3:
                    pid = parts[1]
                    try:
                        fd_count = len([l for l in lines if l.split()[1] == pid]) if pid.isdigit() else 0
                        if fd_count > 1000:  # Suspicious threshold
                            fd_data['anomalies'].append({
                                'pid': pid,
                                'fd_count': fd_count,
                                'status': 'High FD count'
                            })
                    except (IndexError, ValueError):
                        continue

        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("lsof not available")

        return fd_data


class KernelModuleAnalyzer:
    """Analyze loaded kernel modules"""

    @staticmethod
    def list_loaded_modules() -> List[Dict]:
        """List all loaded kernel modules"""
        modules = []

        try:
            with open('/proc/modules', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        modules.append({
                            'name': parts[0],
                            'size': parts[1],
                            'used_by': parts[2],
                            'state': 'loaded'
                        })
        except FileNotFoundError:
            logger.warning("/proc/modules not available")

        return modules

    @staticmethod
    def check_suspicious_modules() -> List[Dict]:
        """Identify suspicious kernel modules"""
        suspicious = []
        modules = KernelModuleAnalyzer.list_loaded_modules()

        # Suspicious keywords
        suspicious_keywords = ['rootkit', 'hook', 'intercept', 'hide', 'bpf', 'trace']

        for module in modules:
            module_name = module['name'].lower()
            for keyword in suspicious_keywords:
                if keyword in module_name:
                    suspicious.append({
                        'module': module['name'],
                        'reason': f'Contains keyword: {keyword}'
                    })
                    break

        return suspicious


class MemoryAnalyzer:
    """Analyze kernel memory for anomalies"""

    @staticmethod
    def check_bpf_memory_region() -> Dict:
        """Check BPF memory region in /proc/meminfo"""
        memory_info = {}

        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        if 'BPF' in key or 'Slab' in key:
                            memory_info[key] = value

        except FileNotFoundError:
            logger.warning("/proc/meminfo not available")

        return memory_info

    @staticmethod
    def analyze_bpf_maps_memory() -> Dict:
        """Analyze total memory used by BPF maps"""
        memory_usage = {
            'total_map_memory': 0,
            'maps': []
        }

        try:
            result = subprocess.run(
                ['bpftool', 'map', 'show', '-j'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.stdout:
                maps = json.loads(result.stdout)
                if isinstance(maps, list):
                    for bpf_map in maps:
                        size = bpf_map.get('value_size', 0) * bpf_map.get('max_entries', 0)
                        memory_usage['total_map_memory'] += size
                        memory_usage['maps'].append({
                            'name': bpf_map.get('name'),
                            'estimated_size_bytes': size
                        })

        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

        return memory_usage


class SecurityPolicyAnalyzer:
    """Analyze security policies and their effectiveness"""

    @staticmethod
    def check_capabilities() -> Dict:
        """Check process capabilities"""
        caps_info = {
            'bounding_set': None,
            'inheritable': None,
            'ambient': None
        }

        try:
            with open('/proc/sys/kernel/cap_last_cap', 'r') as f:
                caps_info['cap_max'] = int(f.read().strip())
        except (FileNotFoundError, ValueError):
            pass

        return caps_info

    @staticmethod
    def check_smack_apparmor_selinux() -> Dict:
        """Check LSM frameworks"""
        lsm_status = {
            'smack': False,
            'apparmor': False,
            'selinux': False
        }

        smack_path = Path('/sys/fs/smackfs')
        lsm_status['smack'] = smack_path.exists()

        apparmor_path = Path('/sys/module/apparmor')
        lsm_status['apparmor'] = apparmor_path.exists()

        selinux_path = Path('/sys/fs/selinux')
        lsm_status['selinux'] = selinux_path.exists()

        return lsm_status

    @staticmethod
    def get_active_lsm() -> List[str]:
        """Get list of active LSMs"""
        active_lsms = []

        try:
            with open('/sys/kernel/security/lsm', 'r') as f:
                lsm_list = f.read().strip().split(',')
                active_lsms = [lsm.strip() for lsm in lsm_list]
        except FileNotFoundError:
            logger.warning("LSM list not available")

        return active_lsms


def generate_forensic_report(output_file: str = '/tmp/bpf_forensics.json'):
    """Generate comprehensive forensic report"""
    report = {
        'bpf_forensics': BPFForensics.check_program_verifier(),
        'kernel_modules': KernelModuleAnalyzer.check_suspicious_modules(),
        'memory_analysis': MemoryAnalyzer.analyze_bpf_maps_memory(),
        'security_policy': {
            'capabilities': SecurityPolicyAnalyzer.check_capabilities(),
            'lsm_available': SecurityPolicyAnalyzer.check_smack_apparmor_selinux(),
            'active_lsm': SecurityPolicyAnalyzer.get_active_lsm()
        }
    }

    # Write report
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    logger.info(f"Forensic report written to {output_file}")
    return report


def main():
    """Main entry point"""
    if os.geteuid() != 0:
        logger.error("This script requires root privileges")
        sys.exit(1)

    import argparse
    parser = argparse.ArgumentParser(description='Advanced BPF Forensics Tool')
    parser.add_argument('--bytecode', type=int, help='Dump bytecode for program ID')
    parser.add_argument('--inspect-map', type=int, help='Inspect BPF map contents')
    parser.add_argument('--trace-syscalls', type=str, help='Trace syscalls for command')
    parser.add_argument('--memory', action='store_true', help='Analyze BPF memory usage')
    parser.add_argument('--report', action='store_true', help='Generate full forensic report')
    parser.add_argument('--modules', action='store_true', help='List suspicious modules')

    args = parser.parse_args()

    try:
        if args.bytecode:
            print(BPFForensics.dump_program_bytecode(args.bytecode))
        elif args.inspect_map:
            contents = BPFForensics.inspect_map_contents(args.inspect_map)
            for entry in contents:
                print(f"Entry {entry['entry']}: {entry['data']}")
        elif args.trace_syscalls:
            data = SystemCallTracer.trace_syscalls(args.trace_syscalls)
            print(json.dumps(data, indent=2))
        elif args.memory:
            memory = MemoryAnalyzer.analyze_bpf_maps_memory()
            print(json.dumps(memory, indent=2))
        elif args.modules:
            suspicious = KernelModuleAnalyzer.check_suspicious_modules()
            if suspicious:
                print("Suspicious modules detected:")
                for mod in suspicious:
                    print(f"  - {mod['module']}: {mod['reason']}")
            else:
                print("No suspicious modules detected")
        elif args.report:
            report = generate_forensic_report()
            print(json.dumps(report, indent=2))
        else:
            parser.print_help()

    except KeyboardInterrupt:
        logger.info("\nAnalysis interrupted")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
