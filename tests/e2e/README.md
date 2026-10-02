# iwp end-to-end tests (Rocky 9 VM)

The whole lifecycle on a real host: image build, `new`/`setup`, deploy, nginx, SELinux
(enforcing), wp-cli, automatic and manual rollback, GC, cron, `[wpcli] mounts`, `iwp verify`,
`iwp import`, alert mail, the egress filter and the in-container hardening. A second pass runs on a VM with SELinux disabled.

## Files

| File | Runs | Purpose |
|---|---|---|
| `vm.sh` | host | `create [--selinux-disabled]` / `start` / `ssh <cmd>` / `push <file> <dest>` / `destroy` a libvirt user-session VM (Rocky 9 GenericCloud, 4 GiB, 2 vCPUs, 30G overlay, SSH via passt). `IWP_E2E_NAME` (default `iwp-e2e`) and `IWP_E2E_PORT` (default `2222`) pick the domain and port, so both passes can run side by side. `--selinux-disabled` adds `selinux=0` to the kernel command line (RHEL 9 no longer disables SELinux through `/etc/selinux/config` alone), sets `SELINUX=disabled`, restarts the domain and checks that `getenforce` says `Disabled` |
| `provision.sh` | VM, root | MariaDB (listening on all addresses; only SSH is forwarded) and nginx, podman network, `/usr/local/bin/iwp`, `/etc/iwp/iwp.toml`, `iwp selinux install`, `/etc/hosts`, the probe plugin source, the legacy-site fixtures, the `/srv/iwp/migration` mount (`container_ro_file_t` when enforcing). On a SELinux-disabled VM: `id_offset = 1000000`, `/etc/subuid` and `/etc/subgid` covering 100000–296607, and logging shims for the SELinux tools (see x1) |
| `scenarios.sh` | VM, root | one function per scenario; prints `PASS <n>` / `FAIL <n>: <why>`, exits non-zero on any FAIL. `scenarios.sh 6 8` runs a subset. The default order depends on `getenforce` (see Scenarios) |
| `fixtures/e2e-probe/` | | path-source plugin that adds `X-IWP-E2E-Probe` to front-end responses |
| `fixtures/e2e-probe-fatal/` | | same slug, fatal error on load (deploy must roll back) |
| `fixtures/legacy/` | | for the imported legacy site: a custom plugin (`legacy-custom`, adds `X-IWP-E2E-Legacy`) and a PNG for `wp media import` |

## Run

Needs `virt-install`, `virsh`, `qemu-img`, `passt` and `~/.ssh/id_ed25519`. If
`virt-install` is missing: `sudo dnf install -y virt-install`.

```bash
scripts/check.sh                       # prints the static binary path
BIN=target/alpine/x86_64-unknown-linux-musl/release/iwp   # or target/x86_64-unknown-linux-musl/…
V=tests/e2e/vm.sh
$V create                              # ~2 min (plus a one-time ~600 MB image download)
$V push $BIN /tmp/iwp
$V push tests/e2e/fixtures/e2e-probe/e2e-probe.php /tmp/e2e-probe.php
$V push tests/e2e/fixtures/e2e-probe-fatal/e2e-probe.php /tmp/e2e-probe-fatal.php
$V push tests/e2e/fixtures/legacy/legacy-custom.php /tmp/legacy-custom.php
$V push tests/e2e/fixtures/legacy/legacy-pixel.png /tmp/legacy-pixel.png
$V push tests/e2e/provision.sh /tmp/provision.sh
$V push tests/e2e/scenarios.sh /tmp/scenarios.sh
$V ssh 'sudo bash /tmp/provision.sh && sudo bash /tmp/scenarios.sh'   # ~14 min, 10 of it two image builds
$V ssh 'sudo systemctl reboot'         # the first reboot shuts the domain off (virt-install
virsh --connect qemu:///session start iwp-e2e   # --import keeps on_reboot=destroy), so start it again
$V ssh 'sudo bash /tmp/scenarios.sh 13 10'      # after the reboot
$V destroy
```

The SELinux-disabled pass is the same on a second VM:

```bash
export IWP_E2E_NAME=iwp-e2e-nosel IWP_E2E_PORT=2223
$V create --selinux-disabled           # ~2.5 min: one extra poweroff/start for selinux=0
# the same pushes as above, then:
$V ssh 'sudo bash /tmp/provision.sh && sudo bash /tmp/scenarios.sh'   # ~8 min, 5 of it the image build
$V destroy
```

Both VMs fit side by side (8 GiB in total); the two passes then take about as long as the
enforcing one alone.

Scenario state lives in `/var/tmp/iwp-e2e` in the VM. Re-running on the same VM skips site
creation; for a clean result use a fresh VM.

## Scenarios

1. Image build, `iwp new a`, first deploy (exit 0 with the "WordPress is not installed yet"
   warning), `iwp wp a core install …` (wp-cli generates the password; the
   log masks it), `/` and `/wp-login.php` 200, `iwp nginx check a`.
2. Request denials: PHP in uploads 403, plugin PHP 404, `/readme.html` 403/404.
3. Container writes: plugins read-only, uploads writable.
4. Two sites: site b is created and deployed; a's uploads are `s0:c1,c513`; b's identity
   (UID map and `s0:c2,c514`) cannot write a's uploads, while a's identity can (control).
5. A local non-nginx user cannot connect to a's FPM socket.
6. Path plugin + `iwp pin` + deploy + activate: the probe header is served and the plugin's PHP
   URL is 404. The fatal version: deploy exits 1, prints `rolled back to`, `status`/`current`
   show the earlier release, the site is 200 and serves the good probe's header again.
7. `iwp wp a plugin update akismet` exits 2 with the deploy message.
8. Deploy the good source again, `iwp rollback a` returns to scenario 6's good release;
   `releases` shows `*` and `-`; `gc`; the cron timer is active and the cron service runs.
9. `iwp setup a` again keeps the DB password (`podman secret inspect --showsecret` data hash).
11. `[wpcli] mounts = ["/srv/iwp/migration"]`, `iwp setup a`, then
    `iwp wp a eval-file /srv/iwp/migration/x.php --skip-plugins` prints the known string (the
    good release is live here, so `--skip-plugins` is used as the runbook advises, not proven
    necessary); writing into the mount fails with `Read-only file system`.
12. Symlinks in uploads: `<base>` is `0750 root:nginx`; an upload written by the site (`ok.jpg`) is
    200 through `current` → release → www-owned `uploads` link → `shared/uploads`; a link the
    site plants (`podman exec --user 33:33 … ln -s /etc/passwd evil.jpg`) and a root-owned link
    to the site's own file (`foreign.jpg`) are 403 (`disable_symlinks if_not_owner`).
13. After a reboot (`scenarios.sh 13`, see Run): both bases still `0750 root:nginx`, `iwp-a` and
    `iwp-b` active with their sockets, both sites 200, the cron timer active.
14. `rollback --with-db` after a fresh deploy: prints the `db-pre-rollback-*` safety dump (the file
    exists) and `restored from: …/db-<new release>.sql.gz`, `current` is the older release, an
    option written after the deploy is gone. Then a bare `iwp rollback a` (previous newer than
    current) and `iwp rollback a <newer> --with-db` both exit 2 with their messages and change
    nothing.
15. `iwp db restore` while `flock /run/iwp/a.lock` is held: exit 1 `another iwp operation on a is
    in progress`, no safety dump taken.
16. `iwp image build 7.1.2 8.5` (trixie): `php -m` lists imagick, ldap, gd and Zend OPcache, and
    the version is 8.5.x.
v1. `iwp deploy a`, then `iwp verify a` and `iwp verify a --json` report no finding (exit 0).
v2. A file planted by the site (`podman exec --user 33:33 iwp-a sh -c 'echo x > …/uploads/evil.php'`)
    gives exit 3 with `shared_php` (text and `--json`); after removing it, exit 0.
v3. As root, `chmod u+w` and append a byte to a plugin file of the current release: exit 3 with
    `release_modified` and `release_writable` (exactly those kinds in `--json`); `iwp deploy a`
    restores a clean release (exit 0).
v4. `systemctl list-timers` shows `iwp-a-verify.timer`, it is active, and
    `systemctl start iwp-a-verify.service` succeeds on the clean site.
v5. Administrators: `iwp verify a` notes `administrators: admin; …`; with `[verify] admins =
    ["someone-else"]` in the site file it exits 3 with `admin_unexpected admin`; with
    `["admin"]` it exits 0, and `iwp update a --dry-run` does not call the site undeployed.
h1. Hardening: an executable copied into uploads fails with `Permission denied` (noexec).
    A theme planted in `uploads/evil` (its `functions.php` would write `uploads/pwned`) with
    `stylesheet`/`template` set to `../uploads/evil`: the front page and wp-cli run, `pwned`
    never appears, `get_stylesheet_directory()` is `…/themes/.iwp-blocked` (and, as a control
    with the filter removed, `…/themes/../uploads/evil`), the journal has `iwp: blocked theme
    directory`; the options are restored with wp-cli and the site is 200 again.
h3. Alert mail: with `alert_email` and a `sendmail` shim, `iwp deploy a` writes
    `OnFailure=iwp-alert@%n.service` into the verify and update units; a verify run that fails
    on a planted `evil.php` produces a mail to the address with the unit in the subject and
    the `shared_php` finding in the body.
h2. Egress: before the filter the container reaches port 80 of the gateway (control). With
    `[egress] restrict = true` and `iwp egress apply`: the table is loaded and the unit
    enabled, MariaDB (3306) and `api.wordpress.org:443` are reachable, port 80 of the gateway
    is not, the site is 200 and `iwp verify a` is clean; after `nft delete table` verify exits
    3 with `egress_not_loaded`; `apply` loads it again; without `[egress]`, `apply` removes
    table, unit and ruleset file and port 80 is reachable again.
i1. Import. A legacy site is built in `/srv/legacy` with the site's own `iwp-cli` image (run
    directly, `--user 0`, `--network host`, bind mount `:Z`): the official
    `wordpress-<version>.tar.gz` of the image's version unpacked with `tar` (not
    `wp core download`: wp-cli extracts through PHP's PharData, which truncates the 39 paths
    longer than 100 bytes in 7.1.2, so the core and the bundled themes come out broken and
    unlike wordpress.org), `wp config create` for DB `legacy`, user `legacy@localhost` with a
    password containing `'` and `$`, prefix `lg_`, `wp core install`, hello-dolly from
    wordpress.org, the `legacy-custom` fixture, a local edit in the active wordpress.org theme,
    `wp media import`, and a planted symlink `uploads/evil-link.jpg -> /etc/passwd`; the
    webroot is `0750 legacy:legacy`; the uploads also hold Contact Form 7's deny `.htaccess`
    (`wpcf7_uploads/.htaccess`) and a silence `index.php`. Then:
    - a symlinked `wp-config.php` is refused (exit 2, names the path, nothing written);
    - `iwp import legacy` exits 2 with the setfacl guidance and writes nothing (no site
      file, no `/srv/iwp/src/legacy`, no base, legacy tree hash unchanged); the printed
      commands are run, and `setfacl -R` must not have followed the link to `/etc/passwd`;
    - the import again: exit 0; the temporary `u:<www>:x` ACL on the new base is gone again
      including the mask (`getfacl -cpn` is exactly `user::rwx group::r-x other::---`, `ls -ld`
      shows `drwxr-x---` without `+`); hello-dolly `wordpress.org`, `legacy-custom` and the edited
      theme `pinned copy` (summary and `import-report.json`); `[database]` name `legacy`, user
      `legacy`, prefix `lg_`; the symlink is listed as not copied and absent from
      `shared/uploads`; the image is copied; the legacy tree (contents, modes, owners,
      mtimes, link targets) is unchanged; the `legacy@localhost` grants and password hash are
      unchanged and it still logs in over the socket;
    - `iwp deploy legacy` exits 0 without an install warning; with a vhost, `/` is 200 with the
      legacy title and the custom plugin's header, the image is served byte-identical;
      `iwp verify legacy` exits 0 with the notes `shared_htaccess …/wpcf7_uploads/.htaccess` and
      `shared_php_stub …/index.php`, which the import summary also listed;
      `iwp wp legacy plugin is-active legacy-custom` succeeds.
m1. Multisite. `iwp new net`, first deploy and `core install`, `iwp wp net core
    multisite-convert --subdomains --skip-config`, `[config] multisite` added to the site file,
    then two deploys with `iwp wp net site create --slug=sub` in between (`sub.net.test` joins
    `domains` only once the subsite exists, because the smoke test probes every listed
    domain). Both exit 0; the
    second one runs `wp core update-db --url=…` once per site (never `--network`, which needs
    `proc_open`), does not roll back, and `http://net.test/` is 200.
10. `ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts <run start>` shows no denial for `httpd_t` or
    `container_t` (runs last). The start time is stored as `%x %T` under `LC_ALL=C`, the format
    ausearch parses; `--input-logs` is required because ausearch otherwise reads stdin when it
    is not a terminal. An ausearch error other than `<no matches>` is a FAIL.

### SELinux-disabled pass

Order: 1 2 3 6 8 11 m1 v1 v2 v3 v4 w1 i1 x1 (4, 5 and 12 rely on labels or the second site; 10 is
the AVC gate).

w1. `user nginx www-users;` in `nginx.conf`: with the workers outside
    `nginx_group` a.test is no longer 200; `iwp nginx apply a`, `iwp deploy a` and
    `iwp import legacy …` all fail with `usermod -aG nginx nginx && systemctl reload nginx`
    and change nothing (nginx includes, releases, `current`, no import output). After that
    command, a.test is 200 again and `nginx apply` and `deploy` succeed; the import then
    succeeds in i1. The `user nginx www-users;` line stays.
x1. No SELinux tool ran. Method: `provision.sh` puts logging shims for `semanage`,
    `restorecon`, `chcon`, `semodule`, `checkmodule`, `semodule_package` and `setfiles` in
    `/usr/local/sbin`, which comes first in both `scenarios.sh`'s PATH (inherited by iwp) and
    systemd's PATH; each call is appended to `/var/log/iwp-e2e-selinux-calls.log` before the
    real tool runs. x1 runs last and fails if that log is not empty; it then checks that
    `semanage`/`restorecon` resolve to the shims, that systemd's PATH starts with
    `/usr/local/sbin`, and that a control `restorecon -n` call is logged. (iwp has no trace
    switch, and `ausearch`/process accounting say nothing useful with SELinux off.)
