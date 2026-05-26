#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo ./unload.sh)"
  exit 1
fi

echo "[*] Detaching BPF programs..."
rm -rf /sys/fs/bpf/sudoadd

echo "[*] Cleaning up compiled object file..."
rm -f sudoadd.bpf.o

echo "[+] Unloaded successfully."
