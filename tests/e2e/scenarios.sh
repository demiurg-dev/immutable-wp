#!/usr/bin/env bash
# iwp lifecycle scenarios on a provisioned VM (see provision.sh). Runs inside the VM as root.
# Usage: scenarios.sh [n ...]   (default: all, in order). Prints PASS <n> / FAIL <n>: <why>
# and exits non-zero if any scenario failed.
set -uo pipefail
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:$PATH   # sudo's secure_path omits them on Rocky

WP=7.1.2
PHP=8.3
FPM_IMAGE=localhost/iwp-fpm:$WP-php$PHP
SITES=/etc/iwp/sites
VH=/var/www/vhosts
ID_OFFSET=$(sed -n 's/^id_offset *= *//p' /etc/iwp/iwp.toml)   # 100000, or 1000000 on the SELinux-disabled pass
MODE=$(getenforce)   # Enforcing (reference host) or Disabled (selinux=0)
LEGACY=/srv/legacy   # the classic webroot imported by scenario i1
LEGACY_PW="Leg'acy\$e2e-Pw1"   # contains ' and $ on purpose
LEGACY_TITLE='Legacy E2E Site'
SELINUX_LOG=/var/log/iwp-e2e-selinux-calls.log   # written by provision.sh's shims (SELinux-disabled pass)
STATE=/var/tmp/iwp-e2e   # survives across separate invocations (scenario subsets)
mkdir -p "$STATE"
OUT=$STATE/out          # output of the last `run`
FAILED=()

log() { echo "--- $*" >&2; }
pass() { echo "PASS $1"; }
fail() { echo "FAIL $1: $2"; FAILED+=("$1"); }
# run <cmd...>: runs, tees combined output to $OUT, returns the command's exit code.
run() {
  log "\$ $*"
  "$@" >"$OUT" 2>&1
  local rc=$?
  # Never keep a WordPress admin password in the output or the log.
  sed -i -E 's/(Admin password: ).*/\1***/I; s/(admin_password[^:=]*[:=] *)[^ ]+/\1***/I' "$OUT"
  sed 's/^/    /' "$OUT" | tail -n 40 >&2
  return $rc
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
base_id() { echo $((ID_OFFSET + $1 * 65536)); }
current_release() { basename "$(readlink "$VH/$1/current")"; }
site_id() { sed -n 's/^id *= *//p' "$SITES/$1.toml"; }
www_uid() { echo $(($(base_id "$1") + 33)); }
# Sorted unique finding kinds of an `iwp verify --json` document.
json_kinds() {
  python3 -c 'import json,sys; print(" ".join(sorted({f["kind"] for f in json.load(open(sys.argv[1]))["findings"]})))' "$1"
}
timed() { local t0=$SECONDS; "$@"; local rc=$?; log "took $((SECONDS - t0))s: $*"; return $rc; }

# The operator's server block for <site>, written after the site's first deploy (runbook §2).
add_vhost() {
  cat > /etc/nginx/conf.d/e2e-$1.conf <<NGX
server {
    listen 80;
    server_name $1.test;
    include iwp/$1.conf;
}
NGX
  local old p alive
  old=$(pgrep -d ' ' -f '^nginx: worker process')
  nginx -t 2>"$OUT" && systemctl reload nginx || return 1
  # The reload is asynchronous: wait until the old workers are gone (a request for the new
  # name may otherwise reach the old configuration's default server, another site), then
  # until the new server block answers.
  for _ in $(seq 1 40); do
    alive=0
    for p in $old; do kill -0 "$p" 2>/dev/null && alive=1; done
    ((alive)) || break
    sleep 0.5
  done
  for _ in $(seq 1 20); do
    [[ $(code "http://$1.test/wp-admin/install.php") != 404 ]] && return 0
    sleep 0.5
  done
  echo "vhost $1 not live after reload" >"$OUT"; return 1
}

# First deploy of a new site, whose database is still empty: it must succeed with the
# "not installed yet" warning, then WordPress is installed with wp-cli.
first_deploy() {
  local s=$1
  timed run iwp deploy "$s" || return 1
  grep -q "warning: WordPress is not installed yet: run iwp wp $s core install" "$OUT" ||
    { echo "no 'not installed yet' warning" >>"$OUT"; return 1; }
  add_vhost "$s" || return 1
  # No --admin_password: wp-cli generates one and prints it; run() masks it in the log.
  run iwp wp "$s" core install --url="http://$s.test" --title=E2E --admin_user=admin \
    --admin_email="a@$s.test" --skip-email || return 1
  run iwp wp "$s" core is-installed
}

s1() {
  local n=1
  timed run iwp image build $WP $PHP || { fail $n "image build: $(tail -1 "$OUT")"; return; }
  if [[ ! -f $SITES/a.toml ]]; then   # re-runs on the same VM skip creation
    timed run iwp new a --domain a.test --wordpress $WP || { fail $n "new a: $(tail -1 "$OUT")"; return; }
    first_deploy a || { fail $n "deploy a: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  fi
  local c1 c2
  c1=$(code http://a.test/); c2=$(code http://a.test/wp-login.php)
  [[ $c1 == 200 && $c2 == 200 ]] || { fail $n "http a.test/=$c1 wp-login=$c2"; return; }
  run iwp nginx check a || { fail $n "nginx check: $(tail -1 "$OUT")"; return; }
  pass $n
}

s2() {
  local n=2 c plugphp
  run iwp wp a eval 'file_put_contents(WP_CONTENT_DIR."/uploads/x.php","<?php echo 1;");' ||
    { fail $n "could not create uploads/x.php"; return; }
  [[ -f $VH/a/shared/uploads/x.php ]] || { fail $n "uploads/x.php not on the host"; return; }
  c=$(code http://a.test/wp-content/uploads/x.php)
  [[ $c == 403 ]] || { fail $n "uploads/x.php gave $c, want 403"; return; }
  # The release has no plugin yet; nginx must 404 any PHP URL that is not an entry point.
  # Scenario 6 repeats this for the probe plugin's file, which does exist on disk.
  c=$(code http://a.test/wp-content/plugins/akismet/akismet.php)
  [[ $c == 404 ]] || { fail $n "plugin PHP URL gave $c, want 404"; return; }
  c=$(code http://a.test/readme.html)
  [[ $c == 403 || $c == 404 ]] || { fail $n "readme.html gave $c"; return; }
  rm -f "$VH/a/shared/uploads/x.php"   # verify (v1) must find shared/ clean
  pass $n
}

s3() {
  local n=3
  if run podman exec iwp-a sh -c 'touch /var/www/html/wp-content/plugins/x'; then
    fail $n "container could write to plugins/"; return
  fi
  run podman exec iwp-a sh -c 'touch /var/www/html/wp-content/uploads/y' ||
    { fail $n "container could not write uploads/: $(cat "$OUT")"; return; }
  pass $n
}

s4() {
  local n=4 bb ab ctx
  if [[ ! -f $SITES/b.toml ]]; then   # re-runs on the same VM skip creation
    timed run iwp new b --domain b.test --wordpress $WP || { fail $n "new b: $(tail -1 "$OUT")"; return; }
    first_deploy b || { fail $n "deploy b: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  fi
  [[ $(code http://b.test/) == 200 ]] || { fail $n "b.test not 200"; return; }
  ctx=$(ls -dZ "$VH/a/shared/uploads")
  log "a uploads: $ctx"
  [[ $ctx == *:s0:c1,c513\ * ]] || { fail $n "a uploads label: $ctx"; return; }
  bb=$(base_id 2); ab=$(base_id 1)
  # Positive control: a's own identity can write there, so the denial below is real.
  run podman run --rm --user 33:33 --uidmap 0:$ab:65536 --gidmap 0:$ab:65536 \
    --security-opt label=level:s0:c1,c513 -v "$VH/a/shared/uploads:/x" $FPM_IMAGE touch /x/control ||
    { fail $n "control: a's identity could not write a's uploads"; return; }
  rm -f "$VH/a/shared/uploads/control"
  if run podman run --rm --uidmap 0:$bb:65536 --gidmap 0:$bb:65536 \
    --security-opt label=level:s0:c2,c514 -v "$VH/a/shared/uploads:/x" $FPM_IMAGE touch /x/z; then
    fail $n "b's identity wrote into a's uploads"; return
  fi
  pass $n
}

s5() {
  local n=5
  [[ -S /run/iwp/a/php.sock ]] || { fail $n "no socket"; return; }
  if run sudo -u nobody python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/iwp/a/php.sock")'; then
    fail $n "nobody could connect to a's FPM socket"; return
  fi
  pass $n
}

s6() {
  local n=6 before rc
  grep -q '^slug *= *"e2e-probe"' "$SITES/a.toml" || cat >> "$SITES/a.toml" <<'TOML'

[[plugin]]
slug   = "e2e-probe"
source = { path = "/srv/iwp/src/e2e-probe" }
TOML
  run iwp pin a || { fail $n "pin a: $(tail -1 "$OUT")"; return; }
  timed run iwp deploy a || { fail $n "deploy with probe: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  run iwp wp a plugin activate e2e-probe || { fail $n "activate e2e-probe"; return; }
  curl -s -D "$STATE/h" -o "$STATE/body" http://a.test/
  grep -qi '^X-IWP-E2E-Probe: iwp-e2e-probe-v1' "$STATE/h" ||
    { fail $n "probe header missing: $(head -1 "$STATE/h")"; return; }
  [[ -f $VH/a/current/wp-content/plugins/e2e-probe/e2e-probe.php ]] ||
    { fail $n "probe plugin missing from the release"; return; }
  [[ $(code http://a.test/wp-content/plugins/e2e-probe/e2e-probe.php) == 404 ]] ||
    { fail $n "probe plugin PHP reachable over HTTP"; return; }
  before=$(current_release a)
  echo "$before" > "$STATE/a.good-release"
  cp /srv/iwp/src/e2e-probe-fatal.php /srv/iwp/src/e2e-probe/e2e-probe.php
  run iwp pin a || { fail $n "pin a (fatal)"; return; }
  timed run iwp deploy a; rc=$?
  cp /tmp/e2e-probe.php /srv/iwp/src/e2e-probe/e2e-probe.php 2>/dev/null || true
  [[ $rc == 1 ]] || { fail $n "fatal deploy exited $rc, want 1"; return; }
  grep -q 'rolled back to' "$OUT" || { fail $n "no 'rolled back to' in deploy output"; return; }
  run iwp status a
  grep -q "$before" "$OUT" || { fail $n "status does not show $before"; return; }
  [[ $(current_release a) == "$before" ]] || { fail $n "current is $(current_release a), want $before"; return; }
  [[ $(code http://a.test/) == 200 ]] || { fail $n "a.test not 200 after rollback"; return; }
  curl -s -D "$STATE/h" -o /dev/null http://a.test/
  grep -qi '^X-IWP-E2E-Probe: iwp-e2e-probe-v1' "$STATE/h" ||
    { fail $n "probe header missing after the automatic rollback"; return; }
  pass $n
}

s7() {
  local n=7 rc
  run iwp wp a plugin update akismet; rc=$?
  [[ $rc == 2 ]] || { fail $n "exit $rc, want 2"; return; }
  grep -q 'use the site file and `iwp deploy`' "$OUT" || { fail $n "message: $(cat "$OUT")"; return; }
  pass $n
}

s8() {
  local n=8 st good
  good=$(cat "$STATE/a.good-release")
  # After scenario 6's automatic rollback, `previous` is the broken release (the plan's ruling:
  # previous = what current pointed to before the last swap). Deploy the good source again so
  # the default rollback target is the good release from scenario 6.
  cp /tmp/e2e-probe.php /srv/iwp/src/e2e-probe/e2e-probe.php
  run iwp pin a || { fail $n "pin a: $(tail -1 "$OUT")"; return; }
  timed run iwp deploy a || { fail $n "deploy a: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  [[ $(readlink "$VH/a/previous") == "releases/$good" ]] ||
    { fail $n "previous is $(readlink "$VH/a/previous"), want releases/$good"; return; }
  run iwp rollback a || { fail $n "rollback: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  [[ $(current_release a) == "$good" ]] || { fail $n "current is $(current_release a), want $good"; return; }
  [[ $(code http://a.test/) == 200 ]] || { fail $n "a.test not 200 after rollback"; return; }
  run iwp releases a || { fail $n "releases"; return; }
  grep -q '^\* ' "$OUT" && grep -q '^- ' "$OUT" || { fail $n "releases lacks * and -"; return; }
  run iwp gc a || { fail $n "gc: $(tail -1 "$OUT")"; return; }
  st=$(systemctl is-active iwp-a-cron.timer)
  [[ $st == active ]] || { fail $n "cron timer is $st"; return; }
  run systemctl start iwp-a-cron.service || { fail $n "cron service: $(journalctl -u iwp-a-cron.service -n 5 --no-pager)"; return; }
  pass $n
}

s9() {
  local n=9 h1 h2
  h1=$(podman secret inspect --showsecret --format '{{.SecretData}}' iwp-a-db | sha256sum)
  run iwp setup a || { fail $n "setup: $(tail -1 "$OUT")"; return; }
  h2=$(podman secret inspect --showsecret --format '{{.SecretData}}' iwp-a-db | sha256sum)
  [[ -n $h1 && $h1 == "$h2" ]] || { fail $n "db secret changed"; return; }
  [[ $(code http://a.test/) == 200 ]] || { fail $n "a.test not 200 after setup"; return; }
  pass $n
}

# [wpcli] mounts and eval-file.
s11() {
  local n=11
  grep -q '^\[wpcli\]' "$SITES/a.toml" || cat >> "$SITES/a.toml" <<'TOML'

[wpcli]
mounts = ["/srv/iwp/migration"]
TOML
  run iwp setup a || { fail $n "setup: $(tail -1 "$OUT")"; return; }
  run iwp wp a eval-file /srv/iwp/migration/x.php --skip-plugins ||
    { fail $n "eval-file: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  grep -q 'iwp-e2e-migration-ok blog=E2E' "$OUT" || { fail $n "unexpected output: $(cat "$OUT")"; return; }
  run iwp wp a eval 'var_dump(file_put_contents("/srv/iwp/migration/w","x"));' --skip-plugins
  [[ ! -e /srv/iwp/migration/w ]] || { fail $n "mount is writable"; return; }
  grep -q 'Read-only file system' "$OUT" && grep -q 'bool(false)' "$OUT" ||
    { fail $n "write to the mount did not fail with EROFS: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  pass $n
}

# Symlinks in uploads (disable_symlinks if_not_owner + www-owned release links): a normal
# upload is served through current -> release -> uploads link -> shared/uploads; links a
# compromised site plants, or links of another owner, are 403.
s12() {
  local n=12 c
  run iwp wp a eval 'file_put_contents(WP_CONTENT_DIR."/uploads/ok.jpg","iwp-e2e-ok");' ||
    { fail $n "could not create uploads/ok.jpg"; return; }
  [[ $(stat -c %U:%G "$VH/a") == root:nginx && $(stat -c %a "$VH/a") == 750 ]] ||
    { fail $n "base is $(stat -c '%U:%G %a' "$VH/a"), want root:nginx 750"; return; }
  # As the site: a link to a host file (link owner www, target root).
  run podman exec --user 33:33 iwp-a ln -sf /etc/passwd /var/www/html/wp-content/uploads/evil.jpg ||
    { fail $n "could not plant evil.jpg: $(cat "$OUT")"; return; }
  # As another owner (root): a link to the site's own file.
  ln -sfn ok.jpg "$VH/a/shared/uploads/foreign.jpg"
  log "$(ls -ln "$VH/a/shared/uploads" | grep -E 'ok|evil|foreign')"
  c=$(code http://a.test/wp-content/uploads/ok.jpg)
  [[ $c == 200 ]] || { fail $n "uploads/ok.jpg gave $c, want 200"; return; }
  [[ $(curl -s http://a.test/wp-content/uploads/ok.jpg) == iwp-e2e-ok ]] ||
    { fail $n "uploads/ok.jpg has the wrong body"; return; }
  c=$(code http://a.test/wp-content/uploads/evil.jpg)
  [[ $c == 403 ]] || { fail $n "planted uploads/evil.jpg gave $c, want 403"; return; }
  c=$(code http://a.test/wp-content/uploads/foreign.jpg)
  [[ $c == 403 ]] || { fail $n "foreign-owned uploads/foreign.jpg gave $c, want 403"; return; }
  rm -f "$VH/a/shared/uploads/evil.jpg" "$VH/a/shared/uploads/foreign.jpg"
  pass $n
}

# After a reboot (run as `scenarios.sh 13` once the VM is back): the containers start on
# their own and serve, with the 0750 root:nginx base.
s13() {
  local n=13 st s
  for s in a b; do
    [[ $(stat -c '%U:%G %a' "$VH/$s") == 'root:nginx 750' ]] ||
      { fail $n "$s base is $(stat -c '%U:%G %a' "$VH/$s")"; return; }
    for _ in $(seq 1 60); do
      st=$(systemctl is-active "iwp-$s.service")
      [[ $st == active && -S /run/iwp/$s/php.sock ]] && break
      sleep 2
    done
    [[ $st == active ]] || { fail $n "iwp-$s is $st"; return; }
    [[ $(code "http://$s.test/") == 200 ]] || { fail $n "$s.test not 200 after reboot"; return; }
  done
  st=$(systemctl is-active iwp-a-cron.timer)
  [[ $st == active ]] || { fail $n "cron timer is $st after reboot"; return; }
  pass $n
}

# rollback --with-db undoes the last deploy, database included; afterwards both a
# bare rollback and --with-db to the newer release are refused.
s14() {
  local n=14 old new rc
  timed run iwp deploy a || { fail $n "deploy a: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  new=$(current_release a); old=$(basename "$(readlink "$VH/a/previous")")
  [[ $old < $new ]] || { fail $n "previous $old is not older than current $new"; return; }
  run iwp wp a option update iwp_e2e_marker after-deploy || { fail $n "set marker"; return; }
  run iwp rollback a --with-db --yes || { fail $n "rollback --with-db: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  grep -q "^safety dump: $VH/a/backups/db-pre-rollback-" "$OUT" || { fail $n "no safety dump line"; return; }
  [[ -f $(sed -n 's/^safety dump: //p' "$OUT") ]] || { fail $n "safety dump file missing"; return; }
  grep -q "^restored from: $VH/a/backups/db-$new.sql.gz" "$OUT" ||
    { fail $n "did not restore db-$new.sql.gz: $(grep restored "$OUT")"; return; }
  [[ $(current_release a) == "$old" ]] || { fail $n "current is $(current_release a), want $old"; return; }
  [[ $(code http://a.test/) == 200 ]] || { fail $n "a.test not 200 after rollback --with-db"; return; }
  if run iwp wp a option get iwp_e2e_marker; then
    fail $n "the marker written after the deploy survived the DB restore"; return
  fi
  run iwp rollback a --yes; rc=$?
  [[ $rc == 2 ]] && grep -q "is newer than the current release" "$OUT" ||
    { fail $n "bare rollback after a rollback: exit $rc: $(tail -1 "$OUT")"; return; }
  run iwp rollback a "$new" --with-db --yes; rc=$?
  [[ $rc == 2 ]] && grep -q -- "--with-db only undoes the last deploy" "$OUT" ||
    { fail $n "--with-db to the newer release: exit $rc: $(tail -1 "$OUT")"; return; }
  [[ $(current_release a) == "$old" ]] || { fail $n "a refusal changed current"; return; }
  pass $n
}

# db restore refuses while another iwp operation holds the site lock.
s15() {
  local n=15 dump before rc
  dump=$(ls -t "$VH"/a/backups/db-2*.sql.gz | head -1)
  before=$(ls "$VH"/a/backups | wc -l)
  # -o: only flock itself holds the lock, released when it exits after the sleep.
  flock -n -o /run/iwp/a.lock sleep 5 &
  sleep 1
  run iwp db restore a "$dump" --yes; rc=$?
  wait
  [[ $rc == 1 ]] && grep -q 'another iwp operation on a is in progress' "$OUT" ||
    { fail $n "restore under the lock: exit $rc: $(tail -1 "$OUT")"; return; }
  [[ $(ls "$VH"/a/backups | wc -l) == "$before" ]] || { fail $n "a safety dump was taken under the lock"; return; }
  pass $n
}

# The trixie image builds for PHP 8.5 with the extensions sites rely on.
s16() {
  local n=16 m
  timed run iwp image build $WP 8.5 || { fail $n "image build 8.5: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  run podman run --rm "localhost/iwp-fpm:$WP-php8.5" php -m || { fail $n "php -m failed"; return; }
  for m in imagick ldap gd 'Zend OPcache'; do
    grep -qx "$m" "$OUT" || { fail $n "php 8.5 lacks $m"; return; }
  done
  run podman run --rm "localhost/iwp-fpm:$WP-php8.5" php -r 'echo PHP_VERSION, "\n";'
  grep -q '^8\.5\.' "$OUT" || { fail $n "not PHP 8.5: $(cat "$OUT")"; return; }
  pass $n
}

# --- iwp verify -------------------------------------------------------------------------

# v1: a fresh deploy verifies clean, in text and JSON.
sv1() {
  local n=v1 rc
  timed run iwp deploy a || { fail $n "deploy a: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  timed run iwp verify a; rc=$?
  [[ $rc == 0 ]] || { fail $n "verify after deploy: exit $rc: $(tail -5 "$OUT" | tr '\n' ' ')"; return; }
  iwp verify a --json >"$STATE/v.json" 2>"$STATE/v.err"; rc=$?
  [[ $rc == 0 && -z $(json_kinds "$STATE/v.json") ]] ||
    { fail $n "verify --json: exit $rc, kinds '$(json_kinds "$STATE/v.json")'"; return; }
  pass $n
}

# v2: PHP planted in uploads by the site itself is a shared_php finding (exit 3).
sv2() {
  local n=v2 rc
  run podman exec --user 33:33 iwp-a sh -c 'echo x > /var/www/html/wp-content/uploads/evil.php' ||
    { fail $n "could not plant uploads/evil.php: $(cat "$OUT")"; return; }
  run iwp verify a; rc=$?
  [[ $rc == 3 ]] && grep -q '^shared_php .*uploads/evil\.php' "$OUT" ||
    { fail $n "planted evil.php: exit $rc: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  iwp verify a --json >"$STATE/v.json" 2>"$STATE/v.err"; rc=$?
  [[ $rc == 3 && $(json_kinds "$STATE/v.json") == shared_php ]] ||
    { fail $n "verify --json: exit $rc, kinds '$(json_kinds "$STATE/v.json")'"; return; }
  rm -f "$VH/a/shared/uploads/evil.php"
  run iwp verify a; rc=$?
  [[ $rc == 0 ]] || { fail $n "after removing evil.php: exit $rc: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  pass $n
}

# v3: root makes a release file writable and changes it: release_modified + release_writable;
# a redeploy restores a clean release.
sv3() {
  local n=v3 rc f
  f=$(find "$(readlink -f "$VH/a/current")/wp-content/plugins" -type f -name '*.php' | sort | head -1)
  [[ -n $f ]] || { fail $n "no plugin PHP file in the current release"; return; }
  log "tampering with $f"
  chmod u+w "$f" && printf 'x' >> "$f"
  run iwp verify a; rc=$?
  [[ $rc == 3 ]] && grep -q '^release_modified ' "$OUT" && grep -q '^release_writable ' "$OUT" ||
    { fail $n "tampered release: exit $rc: $(tail -4 "$OUT" | tr '\n' ' ')"; return; }
  iwp verify a --json >"$STATE/v.json" 2>"$STATE/v.err"
  [[ $(json_kinds "$STATE/v.json") == 'release_modified release_writable' ]] ||
    { fail $n "verify --json kinds '$(json_kinds "$STATE/v.json")'"; return; }
  timed run iwp deploy a || { fail $n "redeploy: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  run iwp verify a; rc=$?
  [[ $rc == 0 ]] || { fail $n "after the redeploy: exit $rc: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  pass $n
}

# v4: deploy enabled the daily verify timer; the service passes on a clean site.
sv4() {
  local n=v4 st
  run systemctl list-timers --all iwp-a-verify.timer
  grep -q 'iwp-a-verify.timer' "$OUT" || { fail $n "list-timers lacks iwp-a-verify.timer"; return; }
  st=$(systemctl is-active iwp-a-verify.timer)
  [[ $st == active ]] || { fail $n "verify timer is $st"; return; }
  run systemctl start iwp-a-verify.service ||
    { fail $n "verify service: $(journalctl -u iwp-a-verify.service -n 8 --no-pager | tr '\n' ' ')"; return; }
  pass $n
}

# v5: administrator accounts. Undeclared they are a note; with [verify] admins every other
# administrator is a finding. The list is read from the site file, without a deploy.
sv5() {
  local n=v5 rc
  run iwp verify a; rc=$?
  [[ $rc == 0 ]] && grep -q '^note: administrators: admin; ' "$OUT" ||
    { fail $n "undeclared admins: exit $rc: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  printf '\n[verify]\nadmins = ["someone-else"]\n' >> "$SITES/a.toml"
  run iwp verify a; rc=$?
  [[ $rc == 3 ]] && grep -q '^admin_unexpected admin: ' "$OUT" ||
    { fail $n "unexpected admin: exit $rc: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  sed -i 's/^admins = .*/admins = ["admin"]/' "$SITES/a.toml"
  run iwp verify a; rc=$?
  [[ $rc == 0 ]] || { fail $n "declared admin: exit $rc: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  # Not release content: the site still counts as deployed for `iwp update`.
  run iwp update a --dry-run
  if grep -q 'changes that are not deployed' "$OUT"; then
    fail $n "[verify] admins made the site look undeployed"; return
  fi
  sed -i '/^\[verify\]$/d; /^admins = /d' "$SITES/a.toml"
  pass $n
}

# h1: writable mounts are noexec, and a theme directory the database points at a writable
# location (stylesheet/template = ../uploads/evil) is never included.
sh1() {
  local n=h1 up=/var/www/html/wp-content/uploads old_s old_t c
  if run podman exec --user 33:33 iwp-a sh -c "cp /bin/true $up/t && chmod 755 $up/t && $up/t"; then
    fail $n "an executable written to uploads ran"; return
  fi
  grep -qi 'permission denied' "$OUT" || { fail $n "expected 'Permission denied': $(tail -1 "$OUT")"; return; }
  rm -f "$VH/a/shared/uploads/t"
  old_s=$(iwp wp a option get stylesheet 2>/dev/null); old_t=$(iwp wp a option get template 2>/dev/null)
  [[ -n $old_s && -n $old_t ]] || { fail $n "could not read the theme options"; return; }
  run podman exec -i --user 33:33 iwp-a sh -c "mkdir -p $up/evil && : > $up/evil/style.css && cat > $up/evil/functions.php" <<'PHP' ||
<?php file_put_contents( WP_CONTENT_DIR . '/uploads/pwned', 'x' );
PHP
    { fail $n "could not plant the theme: $(cat "$OUT")"; return; }
  run iwp wp a option update stylesheet ../uploads/evil && run iwp wp a option update template ../uploads/evil ||
    { fail $n "could not set the theme options: $(tail -1 "$OUT")"; return; }
  c=$(code http://a.test/); log "front page with the planted theme: $c"
  iwp wp a eval 'echo get_stylesheet_directory();' >"$STATE/h1.dir" 2>/dev/null
  # Control: without the guard WordPress resolves the theme into uploads.
  iwp wp a eval 'remove_all_filters( "stylesheet_directory" ); echo get_stylesheet_directory();' >"$STATE/h1.raw" 2>/dev/null
  # The site is repaired with wp-cli while the bad options are still in place.
  run iwp wp a option update stylesheet "$old_s" && run iwp wp a option update template "$old_t" ||
    { fail $n "could not restore the theme options: $(tail -1 "$OUT")"; return; }
  [[ ! -e $VH/a/shared/uploads/pwned ]] ||
    { rm -f "$VH/a/shared/uploads/pwned"; fail $n "functions.php in uploads was executed"; return; }
  grep -q '/themes/\.iwp-blocked$' "$STATE/h1.dir" ||
    { fail $n "theme directory not blocked: $(cat "$STATE/h1.dir")"; return; }
  grep -q '/themes/\.\./uploads/evil$' "$STATE/h1.raw" ||
    { fail $n "control: unguarded directory is $(cat "$STATE/h1.raw")"; return; }
  journalctl -u iwp-a.service --no-pager -n 300 | grep -q 'iwp: blocked theme directory' ||
    { fail $n "no 'blocked theme directory' line in the site's journal"; return; }
  rm -rf "$VH/a/shared/uploads/evil"
  c=$(code http://a.test/)
  [[ $c == 200 ]] || { fail $n "front page after the repair: $c"; return; }
  pass $n
}

# h2: [egress] restrict. A site container reaches MariaDB, DNS and public https, but no other
# port of the host; verify reports a filter that is configured but not loaded; switching it
# off removes it.
sh2() {
  local n=h2 rc probe='exit( @fsockopen( $argv[1], (int) $argv[2], $e, $s, 4 ) ? 0 : 1 );'
  can() { podman exec iwp-a php -r "$probe" "$1" "$2"; }
  can iwp-db-host 80 || { fail $n "control: nginx at the gateway is not reachable before the filter"; return; }
  printf '\n[egress]\nrestrict = true\n' >> /etc/iwp/iwp.toml
  run iwp egress apply || { fail $n "egress apply: $(tail -2 "$OUT" | tr '\n' ' ')"; return; }
  nft list table inet iwp_egress >/dev/null 2>&1 || { fail $n "table inet iwp_egress is not loaded"; return; }
  [[ $(systemctl is-enabled iwp-egress.service) == enabled ]] || { fail $n "iwp-egress.service is not enabled"; return; }
  can iwp-db-host 3306 || { fail $n "MariaDB is not reachable through the filter"; return; }
  if can iwp-db-host 80; then fail $n "port 80 of the host is still reachable"; return; fi
  can api.wordpress.org 443 || { fail $n "public https (and DNS) is not reachable"; return; }
  [[ $(code http://a.test/) == 200 ]] || { fail $n "site a is not 200 with the filter"; return; }
  run iwp verify a; rc=$?
  [[ $rc == 0 ]] || { fail $n "verify with the filter loaded: exit $rc"; return; }
  nft delete table inet iwp_egress
  run iwp verify a; rc=$?
  [[ $rc == 3 ]] && grep -q '^egress_not_loaded ' "$OUT" ||
    { fail $n "verify without the table: exit $rc: $(tail -2 "$OUT" | tr '\n' ' ')"; return; }
  run iwp egress apply && nft list table inet iwp_egress >/dev/null 2>&1 ||
    { fail $n "second apply: $(tail -2 "$OUT" | tr '\n' ' ')"; return; }
  sed -i '/^\[egress\]$/d; /^restrict = true$/d' /etc/iwp/iwp.toml
  run iwp egress apply && grep -q 'filter removed' "$OUT" ||
    { fail $n "removing the filter: $(tail -2 "$OUT" | tr '\n' ' ')"; return; }
  if nft list table inet iwp_egress >/dev/null 2>&1; then fail $n "the table survived the removal"; return; fi
  [[ ! -e /etc/iwp/egress.nft && ! -e /etc/systemd/system/iwp-egress.service ]] ||
    { fail $n "egress files were left behind"; return; }
  can iwp-db-host 80 || { fail $n "port 80 of the host is not reachable again"; return; }
  pass $n
}

# h3: alert_email. Deploy writes OnFailure= into the verify and update units; a failing verify
# run mails its journal through sendmail (a shim that stores the message).
sh3() {
  local n=h3 mail=$STATE/mail i
  cat > /usr/local/sbin/sendmail <<SH
#!/bin/sh
cat > $mail.tmp && mv $mail.tmp $mail
SH
  chmod 0755 /usr/local/sbin/sendmail; rm -f "$mail"
  sed -i '1i alert_email = "ops@a.test"' /etc/iwp/iwp.toml
  h3_cleanup() {
    rm -f "$VH/a/shared/uploads/evil.php" /usr/local/sbin/sendmail
    sed -i '/^alert_email = /d' /etc/iwp/iwp.toml
    systemctl reset-failed iwp-a-verify.service 'iwp-alert@*' 2>/dev/null
  }
  timed run iwp deploy a || { h3_cleanup; fail $n "deploy a: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  grep -qx 'OnFailure=iwp-alert@%n.service' /etc/systemd/system/iwp-a-verify.service &&
    grep -qx 'OnFailure=iwp-alert@%n.service' /etc/systemd/system/iwp-update.service &&
    [[ -f /etc/systemd/system/iwp-alert@.service ]] ||
    { h3_cleanup; fail $n "OnFailure= or the alert unit is missing"; return; }
  echo x > "$VH/a/shared/uploads/evil.php"
  if run systemctl start iwp-a-verify.service; then h3_cleanup; fail $n "verify passed with evil.php planted"; return; fi
  for i in $(seq 20); do [[ -f $mail ]] && break; sleep 1; done
  [[ -f $mail ]] ||
    { journalctl -u 'iwp-alert@*' --no-pager -n 20 >&2; h3_cleanup; fail $n "no mail within 20 s"; return; }
  sed 's/^/    /' "$mail" | head -n 30 >&2
  grep -qx 'To: ops@a.test' "$mail" &&
    grep -q '^Subject: \[iwp\] iwp-a-verify.service failed on ' "$mail" &&
    grep -q 'shared_php .*uploads/evil\.php' "$mail" ||
    { h3_cleanup; fail $n "the mail lacks the recipient, subject or the finding"; return; }
  h3_cleanup
  run iwp verify a || { fail $n "verify after the h3_cleanup: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  pass $n
}

# --- iwp import -------------------------------------------------------------------------

# wp-cli against the legacy webroot: the site's own wp-cli image, run directly as root with a
# bind mount, on the host network so 127.0.0.1:3306 is the host's MariaDB.
lwp() {
  podman run --rm --user 0 --network host -v "$LEGACY:/var/www/html:Z" \
    "localhost/iwp-cli:$WP-php$PHP" php -d memory_limit=512M /usr/local/bin/wp --allow-root \
    --path=/var/www/html "$@"
}

# Contents, types, modes, owners, link targets and mtimes of the legacy tree (not ACLs: the
# runbook's setfacl grant is the one change an operator makes there).
legacy_tree() {
  (cd "$LEGACY" && find . -printf '%y %m %u:%g %T@ %p -> %l\n' | sort &&
    find . -type f -print0 | sort -z | xargs -0 sha256sum) | sha256sum
}

legacy_grants() {
  mariadb -N -e "SHOW GRANTS FOR 'legacy'@'localhost'; SELECT authentication_string FROM mysql.user WHERE user='legacy' AND host='localhost'"
}

# A classic WordPress site in /srv/legacy, as a hand-run host has it: core from wordpress.org,
# a wordpress.org plugin, a custom plugin, a locally edited wordpress.org theme, an uploaded
# image, a symlink in uploads, and a webroot only its own user can enter (0750 legacy).
legacy_build() {
  [[ -f $STATE/legacy.built ]] && return 0
  local theme rel sqlpw=${LEGACY_PW//\'/\'\'}
  id legacy >/dev/null 2>&1 || useradd -r -M -d "$LEGACY" -s /sbin/nologin legacy
  rm -rf "$LEGACY"; install -d -m 0755 "$LEGACY"
  mariadb <<SQL || { echo "creating the legacy database failed" >"$OUT"; return 1; }
CREATE DATABASE IF NOT EXISTS legacy;
CREATE USER IF NOT EXISTS 'legacy'@'localhost' IDENTIFIED BY '$sqlpw';
GRANT ALL PRIVILEGES ON legacy.* TO 'legacy'@'localhost';
SQL
  # The official tarball, unpacked with tar: `wp core download` extracts through PHP's
  # PharData, which truncates the 39 archive paths longer than 100 bytes in 7.1.2 (bundled
  # theme fonts, wp-includes/php-ai-client classes), leaving a broken core and themes that
  # no longer match wordpress.org.
  timed run podman run --rm --user 0 -v "$LEGACY:/var/www/html:Z" "localhost/iwp-cli:$WP-php$PHP" \
    sh -ec "curl -fsSL https://wordpress.org/wordpress-$WP.tar.gz | tar -xz --strip-components=1 -C /var/www/html" ||
    return 1
  [[ -f $LEGACY/wp-content/themes/twentytwentyfour/assets/fonts/instrument-sans/InstrumentSans-VariableFont_wdth,wght.woff2 ]] ||
    { echo "core tarball incomplete" >"$OUT"; return 1; }
  run lwp config create --dbname=legacy --dbuser=legacy --dbpass="$LEGACY_PW" --dbhost=127.0.0.1 \
    --dbprefix=lg_ || return 1
  run lwp core install --url=http://legacy.test --title="$LEGACY_TITLE" --admin_user=admin \
    --admin_email=a@legacy.test --skip-email || return 1
  run lwp plugin install hello-dolly --activate || return 1
  install -d -m 0755 "$LEGACY/wp-content/plugins/legacy-custom"
  install -m 0644 /srv/iwp-e2e-fixtures/legacy-custom.php "$LEGACY/wp-content/plugins/legacy-custom/"
  run lwp plugin activate legacy-custom || return 1
  theme=$(lwp theme list --status=active --field=name 2>/dev/null | tr -d '\r')
  [[ -n $theme && -f $LEGACY/wp-content/themes/$theme/style.css ]] ||
    { echo "no active theme ($theme)" >"$OUT"; return 1; }
  printf '\n/* iwp e2e: a local edit on the legacy host */\n' >> "$LEGACY/wp-content/themes/$theme/style.css"
  echo "$theme" > "$STATE/legacy.theme"
  install -m 0644 /srv/iwp-e2e-fixtures/legacy-pixel.png "$LEGACY/legacy-pixel.png"
  run lwp media import /var/www/html/legacy-pixel.png --title=legacy-pixel || return 1
  rm -f "$LEGACY/legacy-pixel.png"
  rel=$(cd "$LEGACY/wp-content/uploads" && find . -name legacy-pixel.png | sed 's|^\./||' | head -1)
  [[ -n $rel ]] || { echo "uploaded image not found" >"$OUT"; return 1; }
  echo "$rel" > "$STATE/legacy.media"
  ln -s /etc/passwd "$LEGACY/wp-content/uploads/evil-link.jpg"
  # What plugins leave in uploads: Contact Form 7's deny .htaccess and a silence stub.
  install -d -m 0755 "$LEGACY/wp-content/uploads/wpcf7_uploads"
  printf '<Files ~ ".*">\n  Require all denied\n</Files>\n' >"$LEGACY/wp-content/uploads/wpcf7_uploads/.htaccess"
  printf '<?php\n// Silence is golden.\n' >"$LEGACY/wp-content/uploads/index.php"
  chown -R -h legacy:legacy "$LEGACY"
  chmod 0750 "$LEGACY"
  touch "$STATE/legacy.built"
}

# i1: import the legacy site (unreadable uploads first, then symlinks), deploy, serve.
si1() {
  local n=i1 rc h0 g0 www cmds theme rel c
  legacy_build || { fail $n "legacy site: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  theme=$(cat "$STATE/legacy.theme"); rel=$(cat "$STATE/legacy.media")
  # F1: a symlinked wp-config.php is refused (exit 2, names the path) before anything is written.
  mv "$LEGACY/wp-config.php" /root/legacy-wp-config.php
  ln -s /root/legacy-wp-config.php "$LEGACY/wp-config.php"
  run iwp import legacy --from "$LEGACY" --domain legacy.test; rc=$?
  rm -f "$LEGACY/wp-config.php"; mv /root/legacy-wp-config.php "$LEGACY/wp-config.php"
  [[ $rc == 2 ]] && grep -qF "$LEGACY/wp-config.php is a symlink" "$OUT" ||
    { fail $n "symlinked wp-config.php: exit $rc: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  [[ ! -e $SITES/legacy.toml && ! -e /srv/iwp/src/legacy && ! -e $VH/legacy ]] ||
    { fail $n "the symlinked-config import wrote something"; return; }
  h0=$(legacy_tree); g0=$(legacy_grants)
  # The new site user cannot enter the 0750 webroot -> exit 2, setfacl guidance, no writes.
  run iwp import legacy --from "$LEGACY" --domain legacy.test; rc=$?
  [[ $rc == 2 ]] && grep -q 'cannot read' "$OUT" && grep -q 'minimal commands: ' "$OUT" ||
    { fail $n "unreadable uploads: exit $rc: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  [[ ! -e $SITES/legacy.toml && ! -e /srv/iwp/src/legacy && ! -e $VH/legacy ]] ||
    { fail $n "the refused import wrote something"; return; }
  [[ $(legacy_tree) == "$h0" ]] || { fail $n "the refused import changed $LEGACY"; return; }
  # The uid is only known from the message here (the site id is assigned by import).
  cmds=$(sed -n 's/.*minimal commands: //p' "$OUT")
  www=$(sed -n 's/.*setfacl -R -m u:\([0-9]*\):rX .*/\1/p' <<<"$cmds")
  [[ -n $www ]] && grep -qF "setfacl -m u:$www:x $LEGACY;" <<<"$cmds" &&
    grep -qF "setfacl -R -m u:$www:rX $LEGACY/wp-content/uploads" <<<"$cmds" ||
    { fail $n "unexpected setfacl guidance: $cmds"; return; }
  run bash -ec "$cmds" || { fail $n "the printed setfacl commands failed: $(cat "$OUT")"; return; }
  # setfacl -R must not have followed the planted link to /etc/passwd.
  getfacl -cpn /etc/passwd 2>/dev/null | grep -q "^user:$www:" &&
    { fail $n "setfacl -R followed uploads/evil-link.jpg to /etc/passwd"; return; }
  timed run iwp import legacy --from "$LEGACY" --domain legacy.test; rc=$?
  [[ $rc == 0 ]] || { fail $n "import: exit $rc: $(tail -5 "$OUT" | tr '\n' ' ')"; return; }
  [[ $www == "$(www_uid "$(site_id legacy)")" ]] || { fail $n "guidance uid $www is not the site's www uid"; return; }
  # The temporary search ACL for the copy is gone again, mask included: the base has
  # exactly its minimal ACL.
  [[ $(getfacl -cpn "$VH/legacy" | sed '/^$/d' | tr '\n' ' ') == 'user::rwx group::r-x other::--- ' ]] ||
    { fail $n "ACL left on $VH/legacy: $(getfacl -cpn "$VH/legacy" | tr '\n' ' ')"; return; }
  [[ $(ls -ld "$VH/legacy" | cut -c1-10) == drwxr-x--- && $(ls -ld "$VH/legacy" | cut -c11) != + ]] ||
    { fail $n "ls -ld: $(ls -ld "$VH/legacy")"; return; }
  [[ $(stat -c '%U:%G %a' "$VH/legacy") == 'root:nginx 750' ]] ||
    { fail $n "legacy base is $(stat -c '%U:%G %a' "$VH/legacy")"; return; }
  grep -q '^  plugin hello-dolly: wordpress\.org ' "$OUT" &&
    grep -q '^  plugin legacy-custom: pinned copy' "$OUT" &&
    grep -q "^  theme $theme: pinned copy" "$OUT" ||
    { fail $n "package verdicts: $(grep -E '^  (plugin|theme|mu-plugin) ' "$OUT" | tr '\n' ' ')"; return; }
  log "verdicts: $(grep -E '^  (plugin|theme|mu-plugin) ' "$OUT" | tr '\n' ';')"
  python3 - "$VH/legacy/config/import-report.json" "$theme" <<'PY' >"$STATE/i1.py" 2>&1 ||
import json, sys
r = json.load(open(sys.argv[1]))
v = {(p["kind"], p["slug"]): p["verdict"] for p in r["packages"]}
want = {("plugin", "hello-dolly"): "wporg", ("plugin", "legacy-custom"): "source", ("theme", sys.argv[2]): "source"}
bad = {k: v.get(k) for k in want if v.get(k) != want[k]}
sys.exit(f"report verdicts {bad}" if bad else 0)
PY
    { fail $n "$(cat "$STATE/i1.py")"; return; }
  awk '/^\[database\]/{f=1; next} /^\[/{f=0} f' "$SITES/legacy.toml" >"$STATE/i1.db"
  grep -qx 'name = "legacy"' "$STATE/i1.db" && grep -qx 'user = "legacy"' "$STATE/i1.db" &&
    grep -qx 'prefix = "lg_"' "$STATE/i1.db" || { fail $n "[database]: $(tr '\n' ' ' <"$STATE/i1.db")"; return; }
  # The report lists the uploads' .htaccess and silence stub as notes-to-be.
  grep -qF 'wp-content/uploads/wpcf7_uploads/.htaccess (.htaccess/.user.ini: inert' "$OUT" &&
    grep -qF 'wp-content/uploads/index.php (silence stub' "$OUT" ||
    { fail $n "uploads_php lines missing: $(grep -F 'wp-content/uploads/' "$OUT" | tr '\n' ' ')"; return; }
  # The planted link is reported and not copied.
  grep -q '^not copied: symlink wp-content/uploads/evil-link.jpg' "$OUT" ||
    { fail $n "evil-link.jpg not listed as not copied"; return; }
  [[ ! -e $VH/legacy/shared/uploads/evil-link.jpg && ! -L $VH/legacy/shared/uploads/evil-link.jpg ]] ||
    { fail $n "evil-link.jpg was copied"; return; }
  cmp -s "$LEGACY/wp-content/uploads/$rel" "$VH/legacy/shared/uploads/$rel" ||
    { fail $n "uploads/$rel not copied"; return; }
  [[ $(legacy_tree) == "$h0" ]] || { fail $n "import changed $LEGACY"; return; }
  [[ $(legacy_grants) == "$g0" ]] || { fail $n "the legacy@localhost grant or password changed"; return; }
  [[ $(MYSQL_PWD=$LEGACY_PW mariadb -ulegacy -N -e 'SELECT 1' legacy 2>&1) == 1 ]] ||
    { fail $n "legacy@localhost can no longer log in with the old password"; return; }
  log "$(mariadb -N -e "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='legacy'" | tr '\n' ' ')"
  timed run iwp deploy legacy; rc=$?
  [[ $rc == 0 ]] || { fail $n "deploy legacy: exit $rc: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  grep -qiE 'not installed yet|install\.php' "$OUT" && { fail $n "install warning on an imported site"; return; }
  add_vhost legacy || { fail $n "vhost: $(cat "$OUT")"; return; }
  curl -s -D "$STATE/h" -o "$STATE/body" http://legacy.test/
  c=$(head -1 "$STATE/h" | awk '{print $2}')
  [[ $c == 200 ]] && grep -q "<title>$LEGACY_TITLE" "$STATE/body" ||
    { fail $n "legacy.test/ gave $c, title: $(grep -o '<title>[^<]*' "$STATE/body")"; return; }
  grep -qi '^X-IWP-E2E-Legacy: legacy-custom-v1' "$STATE/h" || { fail $n "custom plugin header missing"; return; }
  curl -s -o "$STATE/media" -w '%{http_code}' "http://legacy.test/wp-content/uploads/$rel" >"$STATE/code"
  [[ $(cat "$STATE/code") == 200 ]] && cmp -s "$STATE/media" /srv/iwp-e2e-fixtures/legacy-pixel.png ||
    { fail $n "uploads/$rel gave $(cat "$STATE/code") or wrong bytes"; return; }
  timed run iwp verify legacy; rc=$?
  [[ $rc == 0 ]] || { fail $n "verify legacy: exit $rc: $(tail -4 "$OUT" | tr '\n' ' ')"; return; }
  grep -qF 'shared_htaccess shared/uploads/wpcf7_uploads/.htaccess' "$OUT" &&
    grep -qF 'shared_php_stub shared/uploads/index.php' "$OUT" ||
    { fail $n "verify notes missing: $(tr '\n' ' ' <"$OUT")"; return; }
  run iwp wp legacy plugin is-active legacy-custom || { fail $n "legacy-custom not active"; return; }
  pass $n
}

# --- SELinux-disabled pass ---------------------------------------------------------------

# w1: `user nginx www-users;` puts the workers outside nginx_group: nginx apply,
# deploy and import stop early with the usermod advice and change nothing; after the advice,
# they work.
sw1() {
  local n=w1 rc c ngx rels cur cmd
  legacy_build || { fail $n "legacy site: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  ngx=$(cat /etc/nginx/iwp/* | sha256sum); rels=$(ls "$VH/a/releases" | wc -l); cur=$(current_release a)
  getent group www-users >/dev/null || groupadd www-users
  sed -i -E 's/^user +nginx;/user nginx www-users;/' /etc/nginx/nginx.conf
  grep -q '^user nginx www-users;' /etc/nginx/nginx.conf || { fail $n "could not set the user directive"; return; }
  nginx -t 2>"$OUT" && systemctl reload nginx || { fail $n "reload: $(cat "$OUT")"; return; }
  for _ in $(seq 1 20); do c=$(code http://a.test/); [[ $c != 200 ]] && break; sleep 0.5; done
  log "a.test with workers outside the nginx group: $c"
  [[ $c != 200 ]] || { fail $n "a.test still 200 with the workers outside nginx_group"; return; }
  for cmd in "nginx apply a" "deploy a" "import legacy --from $LEGACY --domain legacy.test"; do
    # shellcheck disable=SC2086
    run iwp $cmd; rc=$?
    [[ $rc != 0 ]] && grep -qF 'usermod -aG nginx nginx && systemctl reload nginx' "$OUT" ||
      { fail $n "iwp $cmd: exit $rc: $(tail -2 "$OUT" | tr '\n' ' ')"; return; }
  done
  [[ $(cat /etc/nginx/iwp/* | sha256sum) == "$ngx" ]] || { fail $n "nginx includes changed"; return; }
  [[ $(ls "$VH/a/releases" | wc -l) == "$rels" && $(current_release a) == "$cur" ]] ||
    { fail $n "a deploy happened"; return; }
  [[ ! -e $SITES/legacy.toml && ! -e /srv/iwp/src/legacy && ! -e $VH/legacy ]] ||
    { fail $n "the refused import wrote something"; return; }
  run bash -c 'usermod -aG nginx nginx && systemctl reload nginx' || { fail $n "usermod: $(cat "$OUT")"; return; }
  for _ in $(seq 1 20); do c=$(code http://a.test/); [[ $c == 200 ]] && break; sleep 0.5; done
  [[ $c == 200 ]] || { fail $n "a.test gave $c after the usermod"; return; }
  run iwp nginx apply a || { fail $n "nginx apply after the fix: $(tail -2 "$OUT" | tr '\n' ' ')"; return; }
  timed run iwp deploy a || { fail $n "deploy after the fix: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
  [[ $(code http://a.test/) == 200 ]] || { fail $n "a.test not 200 after the deploy"; return; }
  pass $n   # import after the fix: scenario i1
}

# x1: with SELinux disabled, nothing iwp ran (setup, deploy, import, verify, ...) called an
# SELinux tool. provision.sh put logging shims for semanage, restorecon, chcon, semodule,
# checkmodule, semodule_package and setfiles first in PATH; a control call proves they log.
sx1() {
  local n=x1 t
  [[ $MODE == Disabled ]] && grep -qw 'selinux=0' /proc/cmdline ||
    { fail $n "not the SELinux-disabled host ($MODE)"; return; }
  if [[ -s $SELINUX_LOG ]]; then
    cat "$SELINUX_LOG"; fail $n "SELinux tools were run: $(head -3 "$SELINUX_LOG" | tr '\n' ' ')"; return
  fi
  for t in semanage restorecon; do
    [[ $(command -v $t) == /usr/local/sbin/$t ]] || { fail $n "$t resolves to $(command -v $t)"; return; }
  done
  [[ $(systemctl show-environment | sed -n 's/^PATH=//p') == /usr/local/sbin:* ]] ||
    { fail $n "systemd PATH does not start with /usr/local/sbin"; return; }
  restorecon -n /var/tmp/iwp-e2e-shim-control 2>/dev/null
  grep -q 'restorecon -n /var/tmp/iwp-e2e-shim-control' "$SELINUX_LOG" ||
    { fail $n "the restorecon shim did not log the control call"; return; }
  : > "$SELINUX_LOG"
  pass $n
}

# A network deployed twice. `wp core update-db --network` makes wp-cli launch a subprocess per
# site, which needs proc_open; the site's disable_functions forbids it, so every forward
# deploy of a network used to roll back. iwp lists the sites and upgrades each one instead.
sm1() {
  local n=m1 r1 r2 c
  grep -q ' net.test' /etc/hosts || echo '127.0.0.1 net.test sub.net.test' >> /etc/hosts
  if [[ ! -f $SITES/net.toml ]]; then
    # Only the main site's domain for now: the smoke test probes every listed domain, and
    # sub.net.test is not a site of the network until it is created below.
    run iwp new net --domain net.test --wordpress $WP ||
      { fail $n "new net: $(tail -1 "$OUT")"; return; }
    first_deploy net || { fail $n "first deploy: $(tail -3 "$OUT" | tr '\n' ' ')"; return; }
    # The image's wp-config.php is read-only; the network constants come from the site file.
    run iwp wp net core multisite-convert --subdomains --skip-config ||
      { fail $n "multisite-convert: $(tail -2 "$OUT" | tr '\n' ' ')"; return; }
    printf '\n[config]\nmultisite = { subdomain = true, domain = "net.test" }\n' >> "$SITES/net.toml"
  fi
  timed run iwp deploy net || { fail $n "deploy 1: $(tail -4 "$OUT" | tr '\n' ' ')"; return; }
  r1=$(current_release net)
  run iwp wp net site list --field=url || { fail $n "site list: $(tail -2 "$OUT" | tr '\n' ' ')"; return; }
  grep -q 'sub\.net\.test' "$OUT" ||
    run iwp wp net site create --slug=sub || { fail $n "site create: $(tail -2 "$OUT" | tr '\n' ' ')"; return; }
  grep -q 'sub\.net\.test' "$SITES/net.toml" ||
    sed -i 's/^domains = \["net\.test"\]/domains = ["net.test", "sub.net.test"]/' "$SITES/net.toml"
  grep -q 'sub\.net\.test' "$SITES/net.toml" || { fail $n "could not add sub.net.test to domains"; return; }
  timed run iwp deploy net || { fail $n "deploy 2: $(tail -4 "$OUT" | tr '\n' ' ')"; return; }
  r2=$(current_release net)
  [[ $r1 != "$r2" ]] || { fail $n "deploy 2 did not activate a new release ($r1)"; return; }
  # One update-db per site of the network, none through --network.
  c=$(grep -c '^\[net\] wp core update-db --url=' "$OUT")
  [[ $c == 2 ]] || { fail $n "expected 2 per-site update-db steps, saw $c: $(grep 'update-db' "$OUT" | tr '\n' ' ')"; return; }
  ! grep -qE 'proc_open|rolling back|rolled back' "$OUT" ||
    { fail $n "deploy 2 rolled back: $(grep -E 'proc_open|roll' "$OUT" | tr '\n' ' ')"; return; }
  c=$(code http://net.test/)
  [[ $c == 200 ]] || { fail $n "http net.test/=$c"; return; }
  pass $n
}

s10() {
  local n=10 since rc
  since=$(cat "$STATE/start")
  # `since` is "%x %T" written under this script's LC_ALL=C, the format ausearch parses here.
  # --input-logs: without it ausearch reads stdin whenever stdin is not a terminal (as under
  # `vm.sh ssh`) and always reports <no matches>.
  # shellcheck disable=SC2086
  ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts $since </dev/null >"$STATE/avc" 2>&1
  rc=$?
  log "ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts $since -> exit $rc: $(head -c 300 "$STATE/avc")"
  if ((rc != 0)) && ! grep -q '<no matches>' "$STATE/avc"; then
    fail $n "ausearch failed (exit $rc): $(head -3 "$STATE/avc" | tr '\n' ' ')"; return
  fi
  if grep -E 'httpd_t|container_t' "$STATE/avc" >/dev/null; then
    cat "$STATE/avc"
    fail $n "AVC denials for httpd_t/container_t since $since"; return
  fi
  pass $n
}

[[ $(id -u) -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -f $STATE/start ]] || date '+%x %T' > "$STATE/start"   # ausearch -ts format (LC_ALL=C)
if [[ $MODE == Disabled ]]; then
  # SELinux disabled: the core subset, verify, the worker-group trap, import, and no
  # SELinux tool calls. 4/5/12 rely on labels or the second site; 10 is the AVC gate.
  ORDER=(1 2 3 6 8 11 m1 v1 v2 v3 v4 v5 h1 h3 h2 w1 i1 x1)
else
  ORDER=(1 2 3 4 5 6 7 8 9 m1 v1 v2 v3 v4 v5 h1 h3 h2 12 14 15 11 i1 16 10)   # 13 runs after a reboot (README)
fi
(($#)) && ORDER=("$@")
T0=$SECONDS
for s in "${ORDER[@]}"; do
  log "scenario $s"
  "s$s"
done
log "total $((SECONDS - T0))s"
((${#FAILED[@]} == 0))
