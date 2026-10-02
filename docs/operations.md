# iwp operations runbook

Everything here was checked against `iwp <cmd> --help`. Host-changing commands need root and
exit 2 before any side effect otherwise. Each `<site>` is validated. Progress goes to stderr as
`[<site>] <step>` lines.

## 1. Host prerequisites

See the README ("Host prerequisites"): podman 5+, mariadb client tools, nginx, the SELinux
tooling, an acl-capable filesystem, and MariaDB listening on the podman gateway IP.

**nginx workers must be in the `nginx_group`.** Site base directories are `0750 root:<nginx_group>`
(default group `nginx`) and the FPM socket directory is reached through the same group. If the
nginx worker processes are not in that group, every request fails with 403/502 while
`nginx -t`, `setup` and `deploy` all succeed, which is hard to diagnose. `setup`, `nginx apply`
and `deploy` therefore read the worker identity from `nginx -T` (the main-context
`user <user> [<group>];` directive; no directive means `nginx`) and stop before changing
anything if `nginx_group` is not among the workers' groups. The check runs in `setup` (so
also `new`, before its site file is written), `nginx apply`, `deploy` and `import` (right
after its root check, before any write). Only `rollback` and `deploy --dry-run` skip it. How
nginx assigns groups: the workers run with the directive's group, or with the group named like
the user when none is given (if no such group exists, nginx fails to start, and iwp reports
the missing group instead of guessing), plus the user's supplementary groups from
`/etc/group`. The user's primary group in `/etc/passwd` does not count unless the user is also
listed as a member.

The usual trap is `user nginx www-users;` in `nginx.conf`: workers then have gid `www-users`
only, and `nginx` the user may not be a member of the `nginx` group. The error names the fix:

```
usermod -aG nginx nginx && systemctl reload nginx     # use your nginx_group name
```

Never "fix" this by setting `nginx_group` to a group that other sites' PHP also runs in (for
example a shared `www-users`): those sites could then read this site's base directory.
Also needed for `iwp import`: `rsync`, `setpriv` (util-linux) and `setfacl` (acl).

Operations that change a site (`setup`, `deploy`, `rollback`, `gc`) hold a per-site lock
`/run/iwp/<site>.lock`. A second one fails with `another iwp operation on <site> is in progress`.
`nginx apply` additionally takes a host-wide lock, `/run/iwp/nginx.lock`. `iwp new` and
`iwp import` take the host-wide `/run/iwp/sites.lock` (waiting for it) while they assign the
new site's id and install its site file, so two concurrent creations never get the same id.

**Database isolation.** Two site files must never share a database or a MariaDB account:
`iwp validate` (and every command that loads the sites) rejects two sites whose effective
`[database] user` or `name` (explicit, or the `iwp_<site>`/`wp_<site>` defaults) are the same.
`setup` (so also `new` and `import`) refuses, before any change, when the account
`'<user>'@'<podman subnet>'` already exists in MariaDB and this site does not own it (its own
stored DB secret names that user, as on a re-run of `iwp setup <site>`): iwp would otherwise
change the password of an account something else uses.

## 2. New site

```
iwp image build <wp-version> <php-version>     # once per WordPress/PHP pair
iwp new <site> --domain example.org --domain www.example.org [--base <path>] [--wordpress <v>] [--php 8.3]
$EDITOR /etc/iwp/sites/<site>.toml             # plugins, themes, php limits, writable paths, [wpcli] mounts
iwp deploy <site>
```

- `iwp new` picks the next free site id, validates everything in memory, installs the site
  file without clobbering an existing one, then runs `iwp setup`. The id is above every
  existing one (ids are never reused) and skips ids whose UID range overlaps `/etc/subuid` or
  `/etc/subgid` (§9). On a fresh host `iwp new` and `iwp import` create `/etc/iwp/sites`
  (`0755 root`).
- `iwp deploy` builds the release, dumps the DB, installs the quadlet and timers, and starts the
  site. `setup` never installs the quadlet, so a host never boots into a site without a release.
- **First deploy of a new site.** The database is still empty, so WordPress redirects to
  `install.php`. On a site's first deploy, the smoke test reports that as a warning, not a
  failure, and the deploy succeeds:

  ```
  [<site>] warning: WordPress is not installed yet: run iwp wp <site> core install --url=… --title=… --admin_user=… --admin_email=…
  ```

  Install it then, from the command line (no web installer needed):

  ```
  iwp wp <site> core install --url=https://example.org --title="Example" \
      --admin_user=admin --admin_email=admin@example.org --skip-email
  ```

  `core install` only writes the database, so `iwp wp` allows it. The warning needs both: no
  release was live before, and the database has **no** table with the site's prefix (iwp
  counts them in `information_schema` before activating). A first deploy against a database
  that already has tables (an imported site, §3) treats the redirect as a failure, like every
  later deploy and every rollback: it means a wrong database name or table prefix.
  Do this before the site is publicly reachable (before adding the include below to a public
  server block): on an empty database `/wp-admin/install.php` lets whoever gets there first
  create the administrator. Use `core multisite-install` for a network.
- In the operator's own `server {}` block (keep `server_name` and TLS; do not set `root` or
  `index`), add one line:

  ```nginx
  include iwp/<site>.conf;
  ```

- `iwp new` already runs `setup`. If you then change `[database]` or `[wpcli]` in the site
  file, run `iwp setup <site>` again before `iwp deploy`. New writable paths need no re-setup;
  deploy handles them.
- Then verify, and reload nginx yourself if you changed the config:

  ```
  iwp nginx check <site>
  ```

  `nginx check` is read-only and reports any server block for the site's domains that lacks the
  include.

## 3. Existing database

Use this when the site already has a database and a hand-written site file.

1. In the site file, name the existing database and a **new, dedicated** user:

   ```toml
   [database]
   name    = "portal"          # the existing database
   user    = "iwp_portal"      # new account, created by iwp
   prefix  = "wp_"             # the existing table prefix
   charset = "utf8mb4"
   collate = ""
   ```

   Defaults when omitted: `wp_<site>`, `iwp_<site>`, `wp_`, `utf8mb4`, `""`.
2. Provision, importing keys and salts from the old config so logins stay valid:

   ```
   iwp setup <site> --salts-from /path/to/old/wp-config.php
   ```

3. Never reuse an account that another application uses. iwp only creates or alters the user
   named in `[database]`, at the podman subnet host pattern, and never touches any other account.
4. `setup` is idempotent. Re-running it keeps the DB password (secret `iwp-<site>-db`) and the
   salts.
   `--salts-from` reads the old config the way PHP does: the first `define` of a key wins,
   commented-out defines (`//`, `#`, `/* */`) are ignored, and an empty value or the sample
   config's `put your unique phrase here` is refused (naming the key). Fix the old config or
   leave out `--salts-from` to generate new salts (this logs everybody out).
   `--salts-from` must name a regular file root can read; a symlink is refused (exit 2), so
   point it at the real file or a regular copy.
5. **MyISAM tables:** the deploy dump uses `--single-transaction`, which does not cover MyISAM.
   If the database has MyISAM tables, quiesce writes (put the site in maintenance mode) for the
   duration of the deploy dump, or the snapshot can be inconsistent.

## 4. Deploy, dry run, automatic rollback, DB restore

```
iwp deploy <site> --dry-run     # build, print the diff against current, delete the build
iwp deploy <site>
```

Deploy order (see `lifecycle::deploy::activate`):

1. Build the release.
2. `prepare_site_dirs`, so writable paths added since `setup` get correct ownership. Until then
   `build_release` creates new shared dirs fail-closed as 0700 root.
3. Write the release's site snapshot (`<base>/config/releases/<release>.json`).
4. Dump the DB to `<base>/backups/db-<release>.sql.gz`. The name is that of the newly deployed
   release, and the dump is taken just before it is activated.
5. Activate: install the nginx include, run `nginx -t` and reload; swap `current` (and
   `previous`); install the quadlet and timers; `systemctl daemon-reload`, `systemd-tmpfiles
   --create`, `restorecon /run/iwp/<site>`; restart the unit; enable the cron timer; wait until
   the FPM socket accepts connections (stops early if the unit is `failed`); empty the `cache`
   dirs.
6. `wp core update-db`, then the smoke test (FastCGI straight to `/run/iwp/<site>/php.sock`,
   so it does not depend on TLS or DNS). For a multisite network iwp lists the sites
   (`wp site list --field=url`) and runs `wp core update-db --url=<url>` for each one. It does
   not use `--network`: wp-cli then starts a subprocess per site, which needs `proc_open`, and
   the default `disable_functions` forbids that.
7. Garbage-collect.

- A failure before step 5 changes nothing live; the unused build is removed.
- If activation fails midway, deploy reactivates the previous release and the error says which
  release is actually current.
- If update-db or the smoke test fails, deploy **rolls back automatically** to the previous
  release and runs the smoke test again (never `update-db`). The report shows both results.
  Only when that automatic rollback succeeded does the report print the restore command; use
  the exact path it prints (it names the dump from step 4). The database is never restored
  automatically:

  ```
  iwp db restore <site> <base>/backups/db-<new-release>.sql.gz --yes
  ```

  `db restore` takes a safety dump of the current state first and prints its path.
- If a first deploy fails there is nothing to roll back to; the error is reported.
- **Time limits.** `wp core update-db` may run 30 minutes, a DB dump 2 hours and a restore
  4 hours. A command that runs longer is stopped (SIGTERM, SIGKILL after 10 s) and the step
  fails with `<program> timed out after <n>s`; for update-db that is a failed check and the
  deploy rolls back. The same limits apply to `iwp update`, `iwp db dump|restore` and
  `rollback --with-db`.
- **After an automatic rollback, `previous` points at the failed release.** `previous` is
  always what `current` pointed to before the last swap, and the automatic rollback was that
  swap. `iwp rollback <site>` without a release argument therefore refuses whenever `previous`
  is newer than `current` (it names both); use `iwp releases <site>` and
  `iwp rollback <site> <release>`, or fix the site file and deploy again.
- If a reactivation itself fails, the report names the release that is actually current and
  prints no restore hint when `current` did not move back.
- Cache-emptying and post-deploy GC failures are warnings in the report, never failures. Cache
  dirs are emptied by an `openat` no-follow walk (contents only; a symlink anywhere is an error).

## 5. `iwp wp` and `iwp shell`

```
iwp wp <site> <wp-cli args…>
iwp shell <site>
```

Both run the site's cli image with the same UID map, SELinux level, secrets, network and
volumes as the site, plus the site's `[wpcli] mounts` (read-only, same path). wp-cli's exit code
is passed through. A TTY is only added when stdin and stdout are terminals.

`iwp wp`, `iwp shell` and `iwp cron` run against the **deployed** release (its site snapshot),
so site-file edits that are not deployed yet never change what they mount or which image they
use. The exception is `[wpcli] mounts`, which is read from the site file every time.

- Code-changing commands (`plugin|theme install|update|delete|uninstall`, `core update|download`,
  `language … install|update|uninstall`) are refused with exit 2. Change the site file and
  `iwp deploy` instead.
- `iwp wp <site> --help` shows iwp's help. For wp-cli help use `iwp wp <site> help <command>`.
- Run scripts from a mounted directory:

  ```toml
  [wpcli]
  mounts = ["/srv/iwp/migration"]
  ```

  ```
  iwp wp <site> eval-file /srv/iwp/migration/fix.php --skip-plugins --skip-themes
  ```

  Use `--skip-plugins` / `--skip-themes` to keep a broken plugin from loading while you work.
- **SELinux:** iwp never relabels `[wpcli] mounts`. Labelling matters only when SELinux is
  enabled; then label them yourself:

  ```
  semanage fcontext -a -t container_ro_file_t '/srv/iwp/migration(/.*)?' && restorecon -R /srv/iwp/migration
  ```

  (or `chcon -R -t container_ro_file_t /srv/iwp/migration`).
- **Plugin activation: one process per plugin.** Some plugins call `exit` inside their
  activation hooks, which kills the wp-cli process and skips everything after it. Activate each
  plugin in its own invocation and verify it:

  ```
  iwp wp <site> plugin activate <slug>
  iwp wp <site> plugin is-active <slug> && echo active
  ```

## 6. Rollback, status, releases, gc

```
iwp rollback <site>                    # re-activate the previous release (refused after any rollback, see §4)
iwp rollback <site> <release>          # a specific release
iwp rollback <site> --with-db --yes    # also restore the DB snapshot
iwp status [<site>] [--json]
iwp releases <site>
iwp gc <site>
```

- Rollback runs the smoke test only, never `wp core update-db`. Each release has a site
  snapshot `<base>/config/releases/<release>.json`; activation renders that release's config
  from it (falling back to the current site file with a warning).
- `--with-db` only undoes the last deploy: the target must be the previous release **and**
  older than the current one. It restores `db-<current>.sql.gz`, the dump taken just before
  the current release replaced the previous one (the same dump the automatic-rollback hint
  names). After a rollback `previous` is newer than `current` and that dump would be the wrong
  state, so it refuses (`--with-db only undoes the last deploy …`). It also refuses if the dump
  file is missing. To restore any other state, use `iwp db restore` explicitly. `--with-db`
  needs `--yes`.
- Order with `--with-db`: first a safety dump of the current state
  (`backups/db-pre-rollback-<timestamp>.sql.gz`, path printed), then the DB restore, and only
  then reactivation of the old release. If reactivation fails, the database stays restored and
  the error says so.
- `status` and `releases` are read-only. A site's base directory is `0750 root:<nginx_group>`,
  so run them as root or as a member of that group.
- `gc` removes releases beyond `keep_releases` (default 5) and pre-deploy dumps
  (`db-<release>.sql.gz`) beyond `keep_db_dumps` (default 10, oldest by mtime first), plus the
  snapshots of removed releases. It never removes `current` or `previous`, and never removes
  your own dumps (`iwp db dump`, `db-<timestamp>.sql.gz`) or the safety dumps
  `db-pre-restore-*` / `db-pre-rollback-*`: delete those yourself. Both settings are in
  `/etc/iwp/iwp.toml`.
- `iwp db dump` and `iwp db restore` take the site lock, so they never run during a deploy,
  update or rollback of the same site (`another iwp operation on <site> is in progress`).
- `iwp image list` shows images and the sites using them. `iwp image prune` removes unreferenced
  images; it never removes an image whose ID cannot be resolved, and removes nothing if any
  site's releases cannot be listed.

## 7. Updates

Dashboard and automatic updates are off by design, so updates happen through iwp.

```
iwp outdated <site>                    # what wordpress.org has (read-only)
iwp update <site> [--dry-run]          # bump versions in the site file and deploy
iwp update --all [--refresh-base]      # every site, as the timer runs it
```

`iwp update` moves wordpress.org plugins and themes to their newest release with the same
major version (see `plugins` below) and core to the newest patch release of its branch, runs a
normal deploy of the updated site (DB dump, smoke test, automatic rollback) and, once the new
versions are live, writes them into the site file (comments kept).

- **The site file is written only after the deploy succeeded**, so it always describes what
  is live, even when the run fails, times out or is killed midway. The exception is a new
  release that stayed live because the automatic rollback itself failed: then the file is
  updated to describe it; the output says which case it is. Edits you make to the file while
  an update runs are kept.
- **Undeployed edits are never activated.** If the site file differs from the deployed release
  (apart from `[wpcli]`, `[update]` and `hold`), the site is not updated and the run exits 1.
  Run `iwp deploy` first.
- **Exit status of `--all`:** sites that were never deployed, are up to date or have
  `auto = false` are reported and are not failures (exit 0). Exit 1 means a real problem: a
  failed or remembered-failed update, undeployed edits, a lookup error, or an invalid site
  file. An invalid site file is reported for that site only; the other sites are still
  updated.
- **`--refresh-base`** first rebuilds the images on a freshly pulled PHP base image. A site
  whose image changed is redeployed even when no version changed; this is how PHP and OS
  security fixes reach the sites.
- **Not covered:** `source` packages (path, git, url; typically premium or custom plugins).
  Update those by hand and `iwp pin`. Plugins removed from wordpress.org show up as
  `lookup failed` and make the run exit 1.
- **Updates that are held back become failures after a deadline.** An update iwp does not take
  on its own is printed as `skipped …`: a plugin or theme major under `plugins = "minor"`, a
  new core branch under `core = "minor"`, or a version that needs a newer PHP or WordPress.
  The first run that sees it records the date in `<base>/config/update-pending.json`. Once it
  has been held back for `[update] overdue_days` (default 30) every run prints
  `<site>: overdue: plugin <slug> -> <version>: held back for <n> days …` and exits 1, until you
  update the package by hand, set `hold = true` on it (you accept the version), or, for core,
  set `core = "major"`. A newer release of the same package does not restart the clock; a
  failed lookup does not either. `overdue_days = 0` switches the deadline off.
- **`source` packages are due for review after a deadline.** iwp cannot look for their
  updates, so it records since when each one has had its current `sha256`. After
  `[update] source_review_days` (default 90) with the same pin, every run prints
  `<site>: overdue: plugin <slug> (url source): unchanged for <n> days …` and exits 1. Check
  the vendor for a newer version; a new pin (`iwp pin` after updating) restarts the clock.
  For code that has no upstream (your own plugins), or once you have reviewed a package and
  want to keep it, set `hold = true` on it. `source_review_days = 0` switches this off.
  The clock starts at the first `iwp update` run with this version of iwp, not at the date the
  package was pinned.
- An update that needs a newer PHP or WordPress than the site runs is skipped and reported.
- **A failed update is not retried by the timer.** The attempt is remembered in
  `<base>/config/update-failed`; the next `--all` run reports the site as not updated (exit 1)
  instead of deploying and rolling back the same versions every night. It retries when the
  set of available updates changes, or when you run `iwp update <site>` yourself.
- The whole update holds the site lock, so it cannot interleave with a manual `iwp deploy`.
- Per site and per package:

  ```toml
  [update]
  auto    = false     # leave this site out of `iwp update --all`
  core    = "minor"   # "minor" (default), "major" or "none"
  plugins = "minor"   # plugins and themes: "minor" (default), "major" or "none"
  overdue_days       = 30   # held-back updates fail the run after this many days; 0: never
  source_review_days = 90   # unchanged source packages fail the run after this; 0: never

  [[plugin]]
  slug    = "woocommerce"
  version = "9.1.2"
  hold    = true      # iwp update leaves it alone and never reports it as overdue
  ```

- **`plugins = "minor"`** (the default) takes only plugin and theme versions with the same
  first number (4.2 → 4.9, not 4.9 → 5.0); a version that is not plain dotted numbers
  (`2.0-beta1`) counts as major. Skipped majors are listed as `skipped … a major update`.
  Take them deliberately: `iwp plugin set <site> <slug>@<version>`, `iwp deploy <site>`, and
  check the site. `"major"` takes every newer release unattended; `"none"` leaves plugins and
  themes to you (they are not even looked up).
- **Plugin database migrations cannot be rolled back with the code.** A plugin migrates its
  tables on the first request (or admin visit) after the new version is live, not during
  `wp core update-db`. If the smoke test then fails and deploy rolls back, or you roll back
  later, the old plugin code runs against the migrated tables. Only the database dump undoes
  that: `iwp rollback <site> --with-db --yes` right after the update, or `iwp db restore` with
  the `db-<release>.sql.gz` the deploy took. This is the main reason the default is `minor`.

**Unattended updates.** Every `setup`/`deploy` installs `iwp-update.service` and
`iwp-update.timer` (nightly at 03:30, `iwp update --all --refresh-base`). iwp never enables
the timer; that is your decision:

```
systemctl enable --now iwp-update.timer
systemctl list-timers iwp-update.timer
journalctl -u iwp-update.service
```

The unit fails when any site failed, was not updated for a reason that needs you (see the
exit status above), had an invalid site file, could not be looked up, or has an overdue update
or source package. Set `alert_email` (§14) to get the journal of a failed run by mail; a run
that fails for an overdue item fails, and mails, every night until the item is dealt with.
The database is never restored
automatically; after a rolled-back update the journal has the exact `iwp db restore` command.

## 7a. Limits and cron

- Each container gets a size-capped `/tmp` and a memory ceiling:

  ```toml
  [limits]
  tmp_size = "1G"     # default (php.post_max_size if that is larger); must be >= post_max_size
  memory   = "4G"     # default: fpm.max_children x php.memory_limit + tmp_size + 384M
  ```

  When the ceiling is hit the kernel kills one process of the container (normally an FPM
  worker, which the master replaces); the site is not restarted (`OOMPolicy=continue`). The
  kill is in `journalctl -k`. Raise `memory` for sites that process large images.
- `iwp cron` (the 5-minute timer) requests `/wp-cron.php` over the site's FPM socket for a
  single site: no container start. It reports whether cron started; errors of individual
  events are in `journalctl -u iwp-<site>`. To run events in the foreground use
  `iwp wp <site> cron event run --due-now`. A multisite network still runs through wp-cli.
  Events now run inside an FPM worker, so they end at `php.max_execution_time` like any
  request. For a site with long-running events (backups, big imports) keep the wp-cli
  behaviour, which is not bound by `max_execution_time` (but see the 240 s limit per wp-cli
  call below):

  ```toml
  [php]
  cron = "cli"
  ```
- **wp-cli cron runs have a 240 s limit per call.** Where `iwp cron` goes through wp-cli
  (`php.cron = "cli"` and every multisite network) each wp-cli call, i.e. each subsite, is
  stopped after 240 s (podman `--timeout`, with a host backstop 30 s later). `iwp cron` then
  continues with the next subsite, prints the error and exits 1 at the end, so one stuck
  site cannot hold the others up until systemd's 10 minute unit limit. An event that legitimately needs more than
  4 minutes is cut off every run: run it by hand with
  `iwp wp <site> cron event run --due-now`, which has no such limit. (The FPM path is bounded
  by `php.max_execution_time` instead.)

## 7b. Symlinks in uploads

The nginx include follows a symlink only when the link and its target have the same owner
(`disable_symlinks if_not_owner`), so a compromised site cannot use a symlink in its uploads to
read another site's files or host files. For this the release's own links into `shared/` are
owned by the site's UID and the SELinux module allows `lnk_file getattr`; `deploy`, `rollback`
and `nginx apply` take care of both before installing the include. After upgrading iwp,
deploy (or `iwp nginx apply`) each site once.

## 8. Hosts with SELinux disabled

SELinux work (policy module, `semanage`, `restorecon`) is skipped cleanly. Nothing else changes.
Sites are then separated by file permissions and user namespaces only: each base directory is
`0750 root:<nginx_group>` and every site has its own UID range.

## 9. `id_offset` and `/etc/subuid` overlaps

Each site gets a UID/GID range derived from `id_offset` (global config, default 100000) and the
site id. `setup` checks `/etc/subuid` and `/etc/subgid` first and refuses to proceed on overlap:

```
<file>:<line>: <name>:<start>:<count> overlaps site <id>'s ID range <lo>..<hi>; change id_offset in iwp.toml or the site id
```

Fix by setting a different `id_offset` in `/etc/iwp/iwp.toml` (before any site is set up, since
it changes every site's identity) or by changing the conflicting `/etc/subuid` entry.

`iwp new` and `iwp import` avoid the situation: the id they choose skips overlapping ranges,
and `iwp import --id <n>` with an overlapping range is refused (exit 2) before anything is
written. The check above still protects hand-written site files and later changes to
`/etc/subuid`.

## 10. Recovery

- **Stale `/run/iwp/nginx-reload-pending`:** a reload failed after the include files were
  already written and tested. Fix the cause (see `systemctl status nginx`), then run
  `iwp nginx apply <site>` for any site. It re-tests and retries the reload, then clears the
  marker. Deleting the marker by hand skips the retry and is not needed.
- **A lock held after a crash:** locks are `flock`s and are released when the process exits, so
  a crashed iwp never leaves one behind. If you still see `another iwp operation on <site> is in
  progress`, another iwp process is really running (`ps`, `fuser /run/iwp/<site>.lock`). Wait for
  it. Do not delete the lock file.
- **Leftover `releases/*.partial` directories** from an interrupted build are removed by the
  next `iwp build`/`iwp deploy`.

## 11. `iwp verify`

```
iwp verify <site> [--json]       # root
```

Read-only. It checks the **live** site and never follows a symlink, so a planted link to `/etc`
cannot make it read the host. What it checks:

- the current release against its own manifest (`.iwp-release.json`): contents, write bits and
  symlinks (this covers wordpress.org and pinned sources alike; plugin checksums are not
  fetched again, the build verified them);
- `<base>/shared` for PHP-like files (`.php`, `.php0`–`.php9`, `.phtml`, `.phar`, `.inc`) and
  for symlinks that leave `shared/`. Two kinds are only **notes**, not findings:
  `.htaccess`/`.user.ini` files (`shared_htaccess <path>`; nginx never reads them and never
  runs PHP there, so plugins such as Contact Form 7 that drop a deny `.htaccess` into uploads
  are harmless) and `.php` "silence" stubs of at most 128 bytes that are empty or hold only an
  opening tag and at most one comment, like WordPress's `<?php // Silence is golden.`
  (`shared_php_stub <path>`). The comment is read the way PHP reads it, so code after a `?>`,
  a bare carriage return or a `#[` attribute is not hidden by it. Any other PHP-like file is
  a finding, including stubs with `exit;` or two comments;
- that the running container `iwp-<site>` uses the release's image;
- the image's core files against wordpress.org's core checksums for the release's version;
- the administrator accounts in the database (see "Administrator accounts" below);
- with `[egress] restrict = true`, that the filter is loaded (§15).

**Exit codes:** 0 clean, 3 findings (they are printed, one per line as
`<kind> <path>: <detail>`, then `N finding(s)`), 1 the check itself could not run (I/O,
podman or network failure), 2 usage error or not root. With `--json` stdout is one JSON
document (`site`, `release`, `findings[] = {kind, path, detail}`, `notes[]`); a failed check
prints `{"site", "error"}` and exits 1. Notes (for example `release <name>: <n> files checked`,
`shared_htaccess shared/uploads/wpcf7_uploads/.htaccess`, `shared_php_stub
shared/uploads/index.php`) go to stderr in text mode and never change the exit code.

**Findings:**

| kind | meaning | what to do |
|---|---|---|
| `release_modified` | a file in `current` differs from the manifest hash | Treat as tampering or disk damage. Compare with `iwp releases`, then redeploy a clean release (`iwp deploy <site>`); investigate how a root-owned read-only file changed. |
| `release_extra` | a file or special file in the release that the manifest does not list | Same as above; find who put it there before redeploying. |
| `release_missing` | the manifest lists a file that is not a regular file in the release | Disk damage or deletion; redeploy. |
| `release_writable` | a file or directory in the release has a write bit | Someone ran `chmod`. Redeploy (a fresh build restores the modes) and find the cause. |
| `release_bad_symlink` | an undeclared symlink in the release, a declared one (uploads, writable paths) that is missing, not a symlink or points elsewhere | Redeploy. If you really want a new writable path, declare it in the site file and deploy. |
| `shared_php` | a PHP-like file under `shared/` (uploads and writable dirs) that is not a silence stub, or a symlink in `shared/` that leaves it (detail says which) | Uploads are never allowed to hold PHP: assume a compromise, look at the file's owner and mtime and the nginx/FPM logs, delete it, find the entry point. Wordfence-style plugin data files are the exception, see `allow_php` below. |
| `container_not_running` | no running container `iwp-<site>` | `systemctl status iwp-<site>`, `journalctl -u iwp-<site>`; start it or redeploy. |
| `image_mismatch` | the container runs a different image than the release expects | The unit was not restarted after a deploy or the image was swapped: `systemctl restart iwp-<site>` or redeploy. |
| `admin_unexpected` | an account with the administrator role (or a network super admin) that `[verify] admins` does not list; the path column is the login | If you did not create it, assume a compromise: remove the account (`iwp wp <site> user delete <login> --reassign=<id>`), change the other administrators' passwords and look for the entry point. If it is legitimate, add the login to `[verify] admins`. |
| `egress_not_loaded` | `[egress] restrict = true`, but the nftables table `inet iwp_egress` is not loaded | Something flushed the ruleset (`nft flush ruleset`, a restart of `nftables.service`). Run `iwp egress apply`. |
| `core_modified` | a core file in the image differs from, is missing from, or is not part of the WordPress core checksums | The image is not what wordpress.org shipped: rebuild with `iwp image build <wp> <php> --refresh-base`, then `iwp update <site>` or `iwp deploy <site>`. |

**The daily timer.** Every deploy installs `iwp-<site>-verify.service` and
`iwp-<site>-verify.timer` and **enables the timer** (`systemctl enable --now`). It runs daily
with `RandomizedDelaySec=1h` and `Persistent=true`, and the service has
`TimeoutStartSec=30min`. A finding makes the unit fail (exit 3), so it shows up in
`systemctl --failed` and `journalctl -u iwp-<site>-verify`; with `alert_email` set (§14) the
findings are mailed. A site that was never deployed has no timer. Run it right after a deploy to confirm
the new release is clean: `iwp verify <site>` must exit 0.

**What is checked is the deployed state.** The set of declared symlinks (uploads and writable
paths) and `allow_php` come from the site snapshot of the **current release**
(`<base>/config/releases/<release>.json`), not from the site file. To change them, edit the
site file and `iwp deploy` again. If the snapshot is missing, verify falls back to the site
file and says so in a note.

**Before the first deploy.** With no release, there is nothing to compare, but `shared/` is
still checked (an import copies uploads there before the first deploy): a clean site prints
`ok` with the note `no release deployed yet` and exits 0.

**Limit.** The `shared/` walk stays on one filesystem (`same_file_system`). If you mount a
separate filesystem on a subtree of `shared/` (a dedicated uploads volume, say), that subtree
is **not scanned**; run a manual `find` there.

### Administrator accounts

Code is read-only, so what an intruder with database access leaves behind is data: typically
a new administrator. `iwp verify` reads the logins of every account with the administrator
role from the site's database (over the MariaDB admin socket, read-only); on a network it
reads the administrators of every site and the super admins.

Without a list they are only shown: `note: administrators: admin, mara; list them in
[verify] admins to have any other reported`. Declare who may be one:

```toml
[verify]
admins = ["admin", "mara"]
```

Every other administrator is then an `admin_unexpected <login>` finding (exit 3, so the
daily timer fails and mails). A listed login that is not an administrator is a note. The
list is read from the site file as it is now, not from the deployed snapshot: adding an
administrator needs an edit, no deploy, and does not make `iwp update` treat the site as
having undeployed changes. Before WordPress is installed the check is skipped with a note.

It compares logins only. It does not notice a changed password or e-mail address of a listed
administrator, or other roles with dangerous capabilities that a plugin added.

### `[verify] allow_php`

Some plugins write PHP into their own data directory. Wordfence keeps `wp-content/wflogs/*.php`;
without an exception `shared_php` would fire on every Wordfence site, every day. Allow exactly
those files:

```toml
[[plugin]]
slug     = "wordfence"
version  = "8.1.0"
writable = ["wp-content/wflogs"]

[verify]
allow_php = ["wp-content/wflogs/*.php"]
```

Rules (checked by `iwp validate`): each entry is a path relative to the WordPress root;
`*` and `?` match within one path segment; only `A-Za-z0-9._-` plus the wildcards are allowed;
no `..`, `.`, empty segments or trailing `/`; it must lie **under a declared `writable` path**;
and **never under `wp-content/uploads`**, which can not be allowlisted. Anything else PHP-like
under `shared/` is still reported. Remember: edit, then `iwp deploy`, for verify to see it.

## 12. Importing a classic WordPress site

`iwp import` adopts an existing classic install (a plain webroot with `wp-config.php`, plugins
and uploads on disk, as on a Plesk or hand-run host). It writes a site file, copies custom code
into pinned sources, provisions the DB user and secrets (through `setup`) and copies the
uploads. It **never deploys, never writes under `--from`** and never touches the old site's
files or database user, so the old site keeps serving throughout.

```
iwp import <site> --from <wp-root> --domain <d> [--domain <d>…] [--base <path>] [--php 8.3] \
           [--new-db-user] [--id <n>] [--json]
```

`--id` sets the site id (1..=511) instead of taking the next free one; use it to keep a
host's ids in a planned order. Its UID range must be free in `/etc/subuid` and `/etc/subgid`.

`--from` is the directory holding `wp-includes/` (a `wp-config.php` one level up is also found).
`--domain` is required unless the old config is a multisite (`DOMAIN_CURRENT_SITE`).
`--php` defaults to 8.3. `--base` is as for `iwp new`.

### Before you start

1. Run as **root** (exit 2 otherwise; no network access and no writes happen before that check). Import also runs the nginx worker-group check (§1) right after it, before any write; `iwp deploy --dry-run` later does not check the worker group.
2. The old site's WordPress version must be installable with `--php` (the import validates
   the pair). `iwp deploy` needs the image: `iwp image build <wp> <php>` (the summary shows
   the detected WordPress version).
3. `rsync`, `setpriv` and `setfacl` must be installed. The uploads are copied **as the new site's www
   user**, never as root, so a swapped symlink in the old uploads cannot make root read other
   files. That user (its uid is derived from `id_offset` and the site id; the error shows it) must therefore be able to read
   the old uploads and enter every directory on the way. Before anything is written, import
   checks this and refuses with exit 2 if it cannot, printing the commands. Example:

   ```
   the new site user (uid 100033) cannot read /var/www/vhosts/example.org/httpdocs/wp-content/uploads; … minimal commands:
   setfacl -m u:100033:x /var/www/vhosts; setfacl -m u:100033:x /var/www/vhosts/example.org;
   setfacl -m u:100033:x /var/www/vhosts/example.org/httpdocs; setfacl -m u:100033:x /var/www/vhosts/example.org/httpdocs/wp-content;
   setfacl -R -m u:100033:rX /var/www/vhosts/example.org/httpdocs/wp-content/uploads
   ```

   Run them (ACLs on the old tree are the one thing you change there; they are harmless to the
   old site and you can remove them afterwards with `setfacl -R -x u:<uid> <path>`), then run the
   import again. Nothing had been written.

   `rsync` or `setfacl` missing is also refused with exit 2 before anything is written (the
   message names the packages, `rsync` and `acl`).

   The site user cannot enter the new site's own base directory either (`0750
   root:<nginx_group>`), so for the copy alone the import grants it a search-only ACL on
   `<base>` (`setfacl -m u:<uid>:x <base>`) and removes it right after rsync, whether the copy
   succeeded or not (`setfacl -x u:<uid> <base>`, then `setfacl -x m:: <base>` for the mask
   entry setfacl added, so the base has its minimal ACL again). If a removal fails, the report
   has a warning with the exact commands to run.
4. `wp-config.php` (in the webroot, or one level up) is read through directory handles and
   never through a symlink: if it is a symlink, the import stops with exit 2 naming the path.
   Replace the link with the real file (or a regular copy root can read) first. If its owner
   differs from the webroot's owner, the report warns: make sure it is this site's config.
5. Long imports (large uploads) should run under `systemd-run --scope` or in `tmux`, so a
   dropped SSH session does not kill them: `systemd-run --scope iwp import …`. Just before
   the uploads copy the import prints the two commands that remove its temporary ACL on
   `<base>` (`setfacl -x u:<uid> <base>; setfacl -x m:: <base>`). If the import is
   interrupted anyway, run exactly those printed commands, then finish with the recovery
   steps below (the site file may already exist).
6. A wp-content that is missing or a symlink is an error. Replace symlinked package
   directories and drop-ins with real copies first, or they are skipped with a warning.

### What import does

1. Reads the old tree (never following symlinks) and `wp-config.php`: DB name, user, password,
   host, prefix, charset, salts, multisite (`DOMAIN_CURRENT_SITE` plus `PATH_CURRENT_SITE`,
   `SITE_ID_CURRENT_SITE` and `BLOG_ID_CURRENT_SITE`, carried into `[config] multisite` as
   `path`, `site_id` and `blog_id` when they differ from `/`, 1, 1), other constants.
2. Classifies each plugin and theme. A package becomes a plain `version` entry only if its
   slug and version exist on wordpress.org **and** its files match (plugins: the per-file
   checksums; themes: the same tree hash as the wordpress.org zip). Anything else becomes a
   pinned `path` source, copied to `/srv/iwp/src/<site>/…` (root-owned, 0644/0755). A failed
   wordpress.org lookup aborts the import before anything is written: it is never treated as
   "clean".
3. Validates the generated site file in memory, then writes it to `/etc/iwp/sites/<site>.toml`
   (never overwriting an existing one), runs `setup` and copies the uploads into
   `<base>/shared/uploads`, then fixes owner and SELinux labels.
4. Writes `<base>/config/import-report.json` (root, 0600) and prints a summary. `--json` prints
   the report as JSON instead.

### Reading the report

Open the report and the site file, then handle each section:

- **`packages`.** One line per plugin, theme and mu-plugin: `wporg` (a `version` entry) or
  `source` with the reason it was not clean, such as `unlisted PHP file evil.php`,
  `missing inc/b.js`, `no version detected`, `single-file package`, `mu-plugin`, a
  checksum mismatch, a theme file that differs, or `cannot classify local files: symlink not
  allowed`. A modified wordpress.org plugin (even one byte, or one extra or missing PHP file)
  is a pinned copy: review the diff against the wordpress.org release; if it is a leftover
  hack or a backdoor, remove it from the site file and use the stock version
  (`iwp plugin set <site> <slug>@<version>`). `skipped` lines were left out of the site file
  (an unusable slug, the reserved mu-plugin name `iwp`, a symlink inside the package): fix
  the cause and add them by hand with `iwp plugin add`.
- **`dropins`.** Files such as `object-cache.php`, `advanced-cache.php`, `db.php`,
  `maintenance.php`, `sunrise.php` in the old `wp-content`. They are **not** copied: without
  a mapping they will not exist and the feature silently disappears. Map each to the plugin
  that ships it:

  ```toml
  [dropins]
  "object-cache.php" = { plugin = "redis-cache", file = "includes/object-cache.php" }
  ```

- **`other_content_dirs`.** Other directories in the old `wp-content` (backups, caches,
  `wflogs`, `ai1wm-backups`…). They are not copied. If a plugin needs one at runtime, declare
  it `writable` on that plugin (`writable = ["wp-content/wflogs"]`; it lives in `shared/` and
  PHP files are denied by nginx), add it to `cache` if it can be emptied on deploy, and add
  `[verify] allow_php` (§11) for plugin data that legitimately contains `.php`. Directories
  you do not need stay behind.
- **`other_root_files`.** Top-level entries of the old webroot that are not WordPress core,
  `wp-config.php` or `wp-content` (dotfiles and directories included, e.g. `.well-known`,
  `robots.txt`, `google…html`, a stray `phpinfo.php`). None is carried. Static files you still
  need: serve them from your server block with a server-level `location = /robots.txt { … }`
  (or `location /.well-known/ { … }`). PHP files in the webroot root are **not supported**
  (`php_entrypoints` only cover plugin files): review them and drop or replace them.
- **`uploads_php`.** PHP-like files, `.htaccess` and `.user.ini` found in the old uploads (up
  to 50), each marked with how `iwp verify` will treat it: `.htaccess`/`.user.ini` and silence
  stubs are only notes; any other PHP file is copied but reported as `shared_php` every day
  until you delete it (uploads can never be allowlisted). A warning counts the real PHP files.
- **`custom_translations`.** Translation files that the new site will not have: files under
  `wp-content/languages/plugins` and `…/themes` that do not belong to a wordpress.org entry
  (whose language packs the build installs), and everything under `languages/loco`. Re-create
  them in the new site (e.g. through Loco Translate after the first deploy) or ship them with a
  pinned plugin.
- **`not_carried`.** `wp-config.php` constants that were not put into `[config]` (names only,
  never values). Constants whose names look like credentials (containing `PASS`, `PASSWORD`,
  `SECRET`, `KEY`, `TOKEN`, `SALT` or `AUTH`) are never carried: the site file is not a secret
  store. The report says "not carried; v1 has no supported way to supply it — move the setting
  into the plugin's options or wait for per-site extra secrets". Non-credential constants you want can be added under `[config.constants]`. v1 has **no
  supported way to ship extra secrets into the container** (iwp provides only the DB and
  salts secrets). Handle credential-looking constants outside iwp, for example by moving the
  setting into the plugin's own options in the database, or wait for a future feature.
- **`warnings`.** Read all of them. Typical ones:
  - a **single-file plugin** (`plugins/foo.php`) is installed as `plugins/foo/foo.php`: its
    plugin file changes, so **re-activate it after the first deploy**
    (`iwp wp <site> plugin activate foo`, one process per plugin, §5);
  - **symlinks** in `wp-content` (plugins, themes, mu-plugins, drop-ins) or in the uploads
    were **not copied**; uploads symlinks are listed under `uploads_not_copied` (at most 20);
  - `DB_HOST` is not `localhost`/`127.0.0.1`/a socket (iwp always connects through the podman
    gateway);
  - a wordpress.org plugin had **local-only files** next to the release (caches, generated
    CSS, logs): they are not carried (count and up to 5 paths); the plugin must recreate them;
  - `UPLOADS` was defined in `wp-config.php`: the copied `wp-content/uploads` may not be where
    the old site really keeps its media; check and copy the right directory;
  - a carried constant points at `localhost`, `127.0.0.1`, `::1` or a unix socket (Redis,
    Memcached…): inside the container that is the container itself, so change it to the
    gateway address or remove it;
  - source files that were not world-readable in the old tree (the copies are 0644; check
    they hold no secrets);
  - some uploads were not readable (rsync exit 23) or vanished (exit 24) during the copy.
    If fewer than 90 % of the files arrived, the import **fails** instead (see Recovery); a
    smaller loss is a warning with the count. After exit 24 on a live site, repeat the
    `setfacl -m`, `rsync` and both `setfacl -x` lines shown under "Recovery" just before the
    cutover.

### Deploy, test, switch

```
$EDITOR /etc/iwp/sites/<site>.toml     # drop-ins, writable dirs, anything from the report
iwp deploy <site> --dry-run
iwp deploy <site>
```

The first deploy of an imported site finds an existing database, so a redirect to
`install.php` is a **failure**, not the warning that a new site gets (§2): it means a wrong
database name or prefix. If you declared a package `writable`, the new directory is created
at deploy.

The new container runs alongside the old site, which keeps serving. Test through a temporary
hostname or an `/etc/hosts` entry on your workstation (`<ip> www.example.org`) pointing to a
server block that includes `iwp/<site>.conf`, then switch the real server blocks: add
`include iwp/<site>.conf;`, remove any server-level `root`/`index` (the include sets them),
`nginx -t`, reload, and check with `iwp nginx check <site>`. Run `iwp verify <site>` (§11),
and stop the old site only after a quiet period (keep its unit and image for a week).

**Fresh uploads.** The import copy is a snapshot. Uploads added to the old site after the
import are not in the new one: repeat the copy just before the cutover with the
`setfacl -m`, `rsync` and both `setfacl -x` lines shown under Recovery (the rsync is idempotent),
or put the old site in maintenance mode.

### The database user

The old site's database stays as it is: the import never alters, drops or grants anything for
the old account `'<user>'@'localhost'`. Two options:

- **Default: keep the existing user name.** `setup` creates the same user name at the podman
  subnet host pattern (for example `'acme'@'10.88.0.0/255.255.0.0'`), with the **old
  password** taken from `wp-config.php` (never printed, never in the site file or argv; it
  goes into the podman secret). The old `localhost` account is a different MariaDB account
  and is not touched, so both sites work at once. Use this when you want the least change
  while the old site is still serving.
- **`--new-db-user`:** creates the dedicated `iwp_<site>` user with a generated password
  instead. Nothing of the old password is reused; again the old account is not touched.
  Prefer this for a permanent setup, and to stop using the old password once it has been
  shared with other systems.

Keeping the old user name is refused (exit 2, use `--new-db-user`) when it is a MariaDB system
account (`root`, `mysql`, `mariadb.sys`, `debian-sys-maint`), when another site file already
uses that name, or when `'<user>'@'<podman subnet>'` already exists in MariaDB (iwp would change
the password of an account it does not own). All three checks run before anything is written.

In both cases the database itself (name and table prefix) stays, so all content comes along.
Salts are imported from the old config, so logins stay valid. MyISAM tables: see §3, point 5.

### Recovery after a late failure

If something fails after the site file was written (setup, the uploads copy, the owner change
or the relabelling), the import stops, **keeps** the site file and the source copies, writes the
report with an `error` and a `recovery` list, and exits 1. If `<base>/config` cannot be written
(setup failed before creating it), the report goes to
`<cache_dir>/import-report-<site>.json` instead and the error names that path.
`import-report.json` holds the exact
commands, equivalent to what the import ran; the `iwp setup` line appears only for a failure
in the setup stage. For example:

```
iwp setup <site> --salts-from /var/www/vhosts/example.org/httpdocs/wp-config.php
setfacl -m u:100033:x <base>
setpriv --reuid=100033 --regid=100033 --clear-groups -- rsync -rtH --no-links --chmod=D2755,F0644 <old>/wp-content/uploads/ <base>/shared/uploads/
setfacl -x u:100033 <base>
setfacl -x m:: <base>
chown -R -h 100033:100033 <base>/shared/uploads
restorecon -RF <base>/shared/uploads
```

The `--salts-from` file must be a regular file root can read (a symlink is refused); if the
old `wp-config.php` has meanwhile become a symlink, point the command at a regular copy.
`iwp setup` after a failed setup keeps a stored DB password or generates a new one; it does not
reuse the old site's password, so a site that kept the old user name gets a different password
in its secret (that is fine for the new site; the old site's account is untouched). Fix the
cause and re-run the printed commands. To start over completely, delete `/etc/iwp/sites/<site>.toml` and the
`/srv/iwp/src/<site>` directory and run `iwp import` again; a leftover site file makes the
import refuse (`site file … already exists`).

## 13. `iwp assets export`

```
iwp assets export <dir>        # no root needed
```

As root, `<dir>` must be root-owned and not group- or other-writable (if it does not exist
yet, the same applies to its parent), so another user cannot redirect the writes; anything
else is refused with exit 2. Files are always created new and never through a symlink.

Writes everything compiled into the binary to `<dir>`, which must be absent or empty (a
non-empty directory is refused, exit 2): `containerfile/` (the image build recipe),
`templates/` (quadlet, nginx, php, timer and systemd templates), `mu-plugin/` (the `iwp`
mu-plugin) and `selinux/iwp.te` (the policy module source). Use it to review exactly what iwp
installs, to diff what a new iwp version would generate, or to audit the SELinux module before
`iwp selinux install`. It only reads the binary; it changes nothing on the host.

## 14. Alert mail

```toml
# /etc/iwp/iwp.toml, before any [table]
alert_email = "ops@example.org"
```

With `alert_email` set, the next `setup` or `deploy` of a site writes
`OnFailure=iwp-alert@%n.service` into that site's `iwp-<site>-verify.service` and into the
host-wide `iwp-update.service`. When one of them fails, systemd starts
`iwp-alert@<unit>.service`, which runs `iwp alert <unit>`: one mail to `alert_email` with the
subject `[iwp] <unit> failed on <hostname>` and the unit's last 200 journal lines (the
findings of a verify run, or the per-site lines of an update run).

- The mail is handed to the host's `sendmail -t -i`, so the host needs a working MTA or a
  sendmail-compatible relay client (postfix, msmtp, …). iwp does not speak SMTP itself. Test
  it: `iwp alert iwp-update.service` sends a mail for that unit right away.
- Existing sites get the line at their next deploy (or `iwp setup <site>`). Removing
  `alert_email` stops the mail at once (`iwp alert` then sends nothing); the `OnFailure=` lines
  disappear at the next deploy.
- Only the verify and update units alert. The 5-minute cron unit and the site container do
  not: they would mail on every hiccup.
- A failing `sendmail` makes `iwp-alert@<unit>.service` fail; it shows in `systemctl --failed`.

## 15. Egress filter

By default a site container can open connections to anything the host can reach: other
services on the host, your internal network, the internet. `[egress]` narrows that for
everything on `podman_network`:

```toml
[egress]
restrict = true                 # default false
ports    = [80, 443, 465, 587]  # TCP ports allowed towards public addresses (the default)
db_port  = 3306                 # MariaDB at the network's gateway (the default)
allow    = ["10.20.0.5:389", "10.20.0.0/24:587"]   # extra "<ipv4>[/<prefix>]:<tcp port>"
```

```
iwp egress show      # print the nftables ruleset (no root, no change)
iwp egress apply     # load it and enable it at boot (root); with restrict = false: remove it
```

What a container may then reach:

| destination | allowed |
|---|---|
| the host itself | MariaDB at the gateway address (`db_port`), DNS (port 53); nothing else, so no SSH, no other site's services, no host nginx |
| any address | DNS (port 53, TCP and UDP), whatever resolver the containers use |
| `allow` entries | that address or network on that TCP port, on the host or elsewhere |
| private, shared, loopback, link-local and multicast ranges (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `169.254/16`, …) | nothing |
| public addresses | TCP on `ports` |

- **Before you switch it on,** list what the sites need on internal addresses and put it in
  `allow`: an LDAP server (authldap), an internal SMTP relay, Redis or a search service on
  another host. Outgoing mail on port 25 is not in the default `ports`.
- **Scope.** The filter matches the source subnet of `podman_network`, so it applies to
  every container on that network, including `iwp wp`/`iwp shell` and image builds, and to
  containers that are not iwp's. Give iwp a network of its own if that matters.
- **How it is installed.** `/etc/iwp/egress.nft` holds a table of its own, `inet
  iwp_egress`, loaded by `iwp-egress.service` (enabled, ordered before the site containers).
  The table only ever drops, so it works next to firewalld and podman's own rules and removing
  it restores the previous behaviour exactly. The ruleset is checked with `nft -c` before
  anything is written. Run `iwp egress apply` again after changing `[egress]` or the network.
- **If the ruleset is flushed** (`nft flush ruleset`, a restart of `nftables.service`) the
  table is gone until the next boot or `iwp egress apply`. `iwp verify` reports that as
  `egress_not_loaded`.
- **IPv4 only.** An IPv6-enabled podman network is not filtered.
- Dropped packets are counted: `nft list table inet iwp_egress`. A site that suddenly cannot
  reach something shows up there and as a timeout in its PHP log.

## 16. Hardening inside the container

Two measures need no configuration; they apply from the next deploy.

- **Writable mounts are `noexec,nosuid,nodev`** (uploads, declared writable directories and
  the socket directory, like `/tmp` before). A site cannot run a binary or load a shared
  library it wrote itself, which is what the usual ways around PHP's `disable_functions`
  need. PHP files are unaffected: `noexec` does not stop PHP from reading a script, the two
  measures below and nginx do that.
- **WordPress never includes code from a writable location.** nginx refuses to run PHP in
  uploads, but WordPress itself includes the active theme's `functions.php` from wherever the
  `stylesheet`/`template` options point, and `../uploads/x` is accepted there; a translation
  file `<locale>.l10n.php` is included the same way. Someone who can write to the database and
  to uploads could use that to run code on every request. The iwp mu-plugin refuses any theme
  directory and any `.php` translation file that PHP could write to. A blocked theme is
  logged (`iwp: blocked theme directory … (writable location; check the stylesheet/template
  options)` in `journalctl -u iwp-<site>`), and the site renders without a theme until the
  options are repaired; wp-cli keeps working for that:
  `iwp wp <site> option update stylesheet <theme>` and the same for `template`.
  `iwp verify` still reports the planted PHP file as `shared_php`.

## 17. Installing from the RPM

```
scripts/rpm.sh                         # on a build machine: dist/iwp-<version>-1.x86_64.rpm
dnf install ./iwp-<version>-1.x86_64.rpm
```

The binary in the package is static, so the same RPM installs on any x86_64 RPM
distribution. It requires podman 5 or newer, nginx, the MariaDB client (`/usr/bin/mariadb`,
`/usr/bin/mariadb-dump`), acl, rsync and util-linux; it recommends
`policycoreutils-python-utils`, `checkpolicy` and `nftables`. `/etc/iwp/iwp.toml` is a config
file: your edits survive upgrades (a changed default arrives as `iwp.toml.rpmnew`). Removing
the package leaves the sites, their units, images and data alone.

**Moving a host from `/usr/local/bin/iwp` to the RPM.** The units already installed
(`iwp-<site>-cron`, `iwp-<site>-verify`, `iwp-update`, `iwp-alert@`) call `/usr/local/bin/iwp`
until they are rewritten, and root's `PATH` finds `/usr/local/bin` first, so the old binary
would keep being used:

```
dnf install ./iwp-<version>-1.x86_64.rpm
ln -sf /usr/bin/iwp /usr/local/bin/iwp     # old units and shells now run the packaged binary
iwp deploy <site>                          # each site: rewrites its units to /usr/bin/iwp
grep -l /usr/local/bin/iwp /etc/systemd/system/iwp-*    # must print nothing
rm /usr/local/bin/iwp
```

If `/etc/iwp/iwp.toml` existed before the first install, rpm keeps yours and writes the
packaged one as `iwp.toml.rpmnew`.

