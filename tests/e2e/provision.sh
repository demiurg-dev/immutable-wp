#!/usr/bin/env bash
# Prepares a fresh Rocky 9 VM for scenarios.sh. Runs inside the VM as root.
# Expects in /tmp: iwp (static binary), e2e-probe.php, e2e-probe-fatal.php, legacy-custom.php,
# legacy-pixel.png.
# Two host flavours, chosen by `getenforce`:
#   Enforcing - the reference host (id_offset 100000, cloud-init's default /etc/subuid).
#   Disabled  - a host with SELinux off (selinux=0), id_offset 1000000 and
#               /etc/subuid covering 100000-296607; logging shims for the SELinux tools.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:$PATH   # sudo's secure_path omits them on Rocky
log() { echo "[provision] $*" >&2; }

[[ $(id -u) -eq 0 ]] || { echo "run as root" >&2; exit 1; }
MODE=$(getenforce)
case $MODE in
  Enforcing) ID_OFFSET=100000 ;;
  Disabled) ID_OFFSET=1000000 ;;
  *) echo "SELinux must be enforcing or disabled (selinux=0), not $MODE" >&2; exit 1 ;;
esac

log "mariadb and nginx"
# MariaDB must accept connections from the podman subnet. 10.88.0.1 only exists once the
# bridge is up, so listen on all addresses; passt forwards only SSH, and firewalld (if
# running) is closed to the outside.
cat > /etc/my.cnf.d/zz-iwp-e2e.cnf <<'CNF'
[mysqld]
bind-address = 0.0.0.0
CNF
systemctl enable --now mariadb nginx
systemctl restart mariadb
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --remove-service=mysql >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null
fi

log "podman default network"
podman network inspect podman >/dev/null

log "iwp binary and global config"
install -m 0755 /tmp/iwp /usr/local/bin/iwp
install -d -m 0755 /etc/iwp /etc/iwp/sites
cat > /etc/iwp/iwp.toml <<TOML
sites_dir      = "/etc/iwp/sites"
cache_dir      = "/var/cache/iwp"
base_root      = "/var/www/vhosts"
keep_releases  = 5
keep_db_dumps  = 10
podman_network = "podman"
mariadb_socket = "/var/lib/mysql/mysql.sock"
nginx_group    = "nginx"
id_offset      = $ID_OFFSET
TOML

if [[ $MODE == Disabled ]]; then
  log "SELinux-disabled host: /etc/subuid and /etc/subgid cover 100000-296607"
  printf '%s\n' rocky:100000:65536 site1:165536:65536 site2:231072:65536 | tee /etc/subuid > /etc/subgid
  # Every SELinux tool iwp could run goes through a shim that logs the call, first in PATH
  # (scenarios.sh and systemd units both search /usr/local/sbin before /usr/sbin). Scenario
  # x1 asserts the log stays empty; it first checks that the shims intercept at all.
  log "SELinux tool shims (/var/log/iwp-e2e-selinux-calls.log)"
  for t in semanage restorecon chcon semodule checkmodule semodule_package setfiles; do
    cat > /usr/local/sbin/$t <<SH
#!/bin/sh
echo "\$(date '+%F %T') ppid=\$PPID (\$(cat /proc/\$PPID/comm 2>/dev/null)) $t \$*" >> /var/log/iwp-e2e-selinux-calls.log
exec /usr/sbin/$t "\$@"
SH
    chmod 0755 /usr/local/sbin/$t
  done
  : > /var/log/iwp-e2e-selinux-calls.log
fi

log "selinux module (skipped by iwp when SELinux is disabled)"
iwp selinux install

log "hosts entries"
# The operator vhosts (/etc/nginx/conf.d/e2e-<site>.conf) are written by scenarios.sh after
# each site's first deploy, as the runbook orders it: `include iwp/<site>.conf` only passes
# `nginx -t` once deploy has installed that include, and a broken include in one vhost would
# fail every other site's nginx test.
grep -q ' a.test' /etc/hosts || echo '127.0.0.1 a.test b.test legacy.test' >> /etc/hosts

log "path plugin source"
install -d -m 0755 /srv/iwp/src/e2e-probe
install -m 0644 /tmp/e2e-probe.php /srv/iwp/src/e2e-probe/e2e-probe.php
install -m 0644 /tmp/e2e-probe-fatal.php /srv/iwp/src/e2e-probe-fatal.php

log "legacy site fixtures (scenario i1)"
install -d -m 0755 /srv/iwp-e2e-fixtures
install -m 0644 /tmp/legacy-custom.php /tmp/legacy-pixel.png /srv/iwp-e2e-fixtures/

log "wp-cli migration mount (operations.md §5)"
install -d -m 0755 /srv/iwp/migration
cat > /srv/iwp/migration/x.php <<'PHP'
<?php
echo "iwp-e2e-migration-ok blog=" . get_option('blogname') . "\n";
PHP
chmod 0644 /srv/iwp/migration/x.php
if [[ $MODE == Enforcing ]]; then
  semanage fcontext -a -t container_ro_file_t '/srv/iwp/migration(/.*)?' 2>/dev/null ||
    semanage fcontext -m -t container_ro_file_t '/srv/iwp/migration(/.*)?'
  restorecon -R /srv/iwp/migration
fi

log "done"
