#!/usr/bin/env bash
# 00-bootstrap.sh — run ONCE inside the VM after booting the live session.
#
# Open Konsole in the live KDE session, then paste:
#
#     sudo mount -t 9p -o trans=virtio,version=9p2000.L rgd /mnt && \
#       bash /mnt/vm-demo/00-bootstrap.sh
#
# This sets a known password for liveuser, starts sshd, installs the
# stress-ng workload generator, drops the host-built rgd binary into place
# with CAP_SYS_RESOURCE, and prints the next-step command to run from the
# host. After this script finishes, the host can drive everything else
# over SSH (port 2222) — you only need to leave the QEMU window visible
# so you can watch KDE's responsiveness during each take.

set -euo pipefail

PASS="rgd-demo"
SHARE=/mnt
ART=$SHARE/vm-demo/artifacts

echo "==> Setting liveuser password to '${PASS}' (for SSH)"
echo "liveuser:${PASS}" | sudo chpasswd

echo "==> Allowing password auth + starting sshd"
sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl enable --now sshd

echo "==> Installing stress-ng (and friends)"
sudo dnf install -y --setopt=install_weak_deps=False stress-ng attr libcap >/dev/null

echo "==> Deploying rgd binary from host build"
sudo install -m 0755 "$SHARE/target/release/rgd" /usr/local/bin/rgd
sudo install -m 0755 "$SHARE/contrib/rgctl/rgctl" /usr/local/bin/rgctl
sudo setcap cap_sys_resource=ep /usr/local/bin/rgd

echo "==> Sanity check: rgd version + capability"
/usr/local/bin/rgd --version
getcap /usr/local/bin/rgd

echo "==> Recording VM env to artifacts/"
mkdir -p "$ART"
{
  echo "# captured $(date -Is)"
  uname -a
  echo "---"
  cat /etc/os-release
  echo "---"
  systemctl --version | head -1
  echo "---"
  ls /sys/fs/cgroup/cgroup.controllers
  cat /sys/fs/cgroup/cgroup.controllers
  echo "---"
  ls /proc/pressure
} > "$ART/00-vm-env.txt"

GUEST_IP=$(hostname -I | awk '{print $1}')
echo
echo "Bootstrap complete."
echo
echo "Drive the rest from the HOST shell:"
echo "  ssh -p 2222 -o StrictHostKeyChecking=no liveuser@127.0.0.1   # password: ${PASS}"
echo
echo "Or paste each take inline in the VM Konsole:"
echo "  bash /mnt/vm-demo/01-baseline.sh"
echo "  bash /mnt/vm-demo/02-dryrun.sh"
echo "  bash /mnt/vm-demo/03-enforce.sh"
echo "  bash /mnt/vm-demo/04-panic.sh"
