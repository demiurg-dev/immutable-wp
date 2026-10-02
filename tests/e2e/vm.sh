#!/usr/bin/env bash
# Rocky 9 VM for the iwp end-to-end run (libvirt user session, SSH forwarded to localhost:2222).
# Usage: vm.sh create [--selinux-disabled] | start | ssh <cmd...> | push <file> <dest> | destroy
# IWP_E2E_NAME / IWP_E2E_PORT select the domain and SSH port, so two VMs can run side by side.
set -euo pipefail

NAME=${IWP_E2E_NAME:-iwp-e2e}
VM_DIR=${IWP_E2E_VM_DIR:-$HOME/vms/iwp-e2e}
PORT=${IWP_E2E_PORT:-2222}
KEY=${IWP_E2E_KEY:-$HOME/.ssh/id_ed25519}
IMAGE_URL=https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2
BASE_IMG=Rocky-9-GenericCloud-Base.latest.x86_64.qcow2
CONNECT=qemu:///session
SSH_OPTS=(-i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR -o ConnectTimeout=5)

vm_ssh() { ssh "${SSH_OPTS[@]}" -p "$PORT" rocky@localhost "$@"; }

wait_ssh() {
  for _ in $(seq 1 120); do
    vm_ssh true 2>/dev/null && return 0
    sleep 5
  done
  echo "VM $NAME did not come up" >&2; exit 1
}

# `virsh start`, then wait for SSH. The first reboot of a fresh domain shuts it off
# (virt-install --import keeps on_reboot=destroy), so a reboot is a poweroff plus this.
start() {
  virsh --connect "$CONNECT" start "$NAME" >/dev/null
  wait_ssh
}

# SELinux disabled the way RHEL 9 requires it: `selinux=0` on the kernel command line
# (SELINUX=disabled in /etc/selinux/config alone no longer disables it), plus the config
# file.
disable_selinux() {
  vm_ssh 'sudo grubby --update-kernel ALL --args selinux=0 &&
    sudo sed -i "s/^SELINUX=.*/SELINUX=disabled/" /etc/selinux/config &&
    sudo systemctl poweroff' || true
  for _ in $(seq 1 60); do
    [[ $(virsh --connect "$CONNECT" domstate "$NAME" 2>/dev/null) == "shut off" ]] && break
    sleep 2
  done
  start
  local st
  st=$(vm_ssh getenforce)
  [[ $st == Disabled ]] || { echo "getenforce reports $st after selinux=0" >&2; exit 1; }
  vm_ssh 'grep -o "selinux=0" /proc/cmdline; getenforce'
}

create() {
  local selinux=enforcing
  case ${1:-} in
    --selinux-disabled) selinux=disabled ;;
    "") ;;
    *) echo "usage: vm.sh create [--selinux-disabled]" >&2; exit 2 ;;
  esac
  command -v virt-install >/dev/null || {
    echo "virt-install missing: run \`sudo dnf install -y virt-install\`" >&2; exit 1; }
  if virsh --connect "$CONNECT" dominfo "$NAME" >/dev/null 2>&1; then
    echo "domain $NAME already exists; run \`vm.sh destroy\` first" >&2; exit 1
  fi
  mkdir -p "$VM_DIR"
  cd "$VM_DIR"
  if [[ ! -f $BASE_IMG ]]; then
    # Per-domain partial file: two `create`s may download at the same time.
    curl -fL --retry 3 -o "$BASE_IMG.$NAME.part" "$IMAGE_URL"
    mv -f "$BASE_IMG.$NAME.part" "$BASE_IMG"
  fi
  rm -f "$NAME.qcow2"
  qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMG" "$NAME.qcow2" 30G
  cat > "$NAME.user-data" <<UD
#cloud-config
users:
  - name: rocky
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys: ["$(cat "$KEY.pub")"]
packages: [podman, nginx, mariadb-server, policycoreutils-python-utils, checkpolicy, acl, rsync, python3, audit, nftables]
UD
  virt-install --connect "$CONNECT" --name "$NAME" --memory 4096 --vcpus 2 \
    --import --disk "$NAME.qcow2" --os-variant rocky9 --cloud-init "user-data=$NAME.user-data" \
    --network "passt,portForward=$PORT:22" --noautoconsole --graphics none
  echo "waiting for SSH and cloud-init..." >&2
  for _ in $(seq 1 120); do
    if vm_ssh 'sudo cloud-init status --wait >/dev/null 2>&1; true' 2>/dev/null; then
      vm_ssh 'sudo cloud-init status; getenforce; rpm -q podman nginx mariadb-server'
      [[ $selinux == disabled ]] && disable_selinux
      return 0
    fi
    sleep 5
  done
  echo "VM did not come up" >&2; exit 1
}

destroy() {
  virsh --connect "$CONNECT" destroy "$NAME" 2>/dev/null || true
  virsh --connect "$CONNECT" undefine "$NAME" --remove-all-storage 2>/dev/null || true
}

cmd=${1:-}; shift || true
case $cmd in
  create) create "$@" ;;
  start) start ;;
  ssh) vm_ssh "$@" ;;
  push) [[ $# -eq 2 ]] || { echo "usage: vm.sh push <file> <dest>" >&2; exit 2; }
        scp "${SSH_OPTS[@]}" -P "$PORT" "$1" "rocky@localhost:$2" ;;
  destroy) destroy ;;
  *) echo "usage: vm.sh create [--selinux-disabled] | start | ssh <cmd> | push <file> <dest> | destroy" >&2; exit 2 ;;
esac
