# iwp — immutable WordPress hosting

`iwp` runs WordPress sites where host nginx serves static files directly and PHP runs in a
read-only php-fpm container. Plugins and themes are pinned per site and mounted read-only;
only uploads and declared directories are writable.

## Why deploy WordPress with iwp

**A compromised site cannot plant code.**

- WordPress core, plugins and themes are read-only for PHP, and nginx refuses to run PHP from
  uploads or any other writable directory. Only a short list of WordPress entry points reaches
  PHP at all.
- Each site runs in its own container with its own UID range and SELinux category, a
  read-only root filesystem, no capabilities and a memory ceiling, so one site cannot read or
  write another.
- nginx only follows a symlink whose owner also owns its target, so a site cannot use its
  uploads to expose another site's files or host files.
- Database passwords and salts are podman secrets. They are never in the image, the site file
  or a release.
- Writable directories are mounted `noexec`, and WordPress is kept from including a theme or
  translation file out of them, so code planted through the database does not run either.
- Optionally the containers' outbound connections are filtered: the database, DNS and public
  web and mail ports, but not the rest of the host or the internal network.

**You know exactly what is running.**

- One file per site declares the WordPress version, PHP version, plugins, themes and
  languages. That file is the site; the dashboard cannot change code.
- Downloads are checked before they are used: core and wordpress.org plugins against the
  published checksums, everything else against a hash pinned in the site file.
- `iwp verify` compares the live site with what was built, daily, and reports PHP files in
  uploads and administrator accounts nobody declared.
- Failed checks and failed or overdue updates are mailed.

**Updates are routine and reversible.**

- A deploy builds a new release, dumps the database, switches atomically and runs a smoke
  test. If the test fails, the previous release is live again without anyone stepping in.
- `iwp update` moves sites to newer core, plugin and theme versions the same way, and a
  nightly timer can do it unattended, including rebuilding the image for PHP and OS fixes.
  Updates it does not take on its own (majors, premium plugins) are reported once they have
  waited too long.
- `iwp rollback` returns to any kept release; for the previous one it can also restore the
  database dump taken when the current release went live.

**It stays lean.**

- Static files are served by host nginx straight from disk. PHP is one hop away over a unix
  socket: no second web server and no proxy layer.
- Static files and PHP always come from the same WordPress version, because both are taken
  from the same image.
- `iwp` is a single static binary on top of nginx, podman and MariaDB (see Host
  prerequisites).

**Existing sites can move in.** `iwp import` adopts a classic WordPress install: it writes the
site file, pins custom code, and copies uploads and secrets without touching the old site.

The price: plugins and themes are installed by editing the site file and deploying, not from
the dashboard, and a plugin that writes into its own directory needs a declared writable path.

## Status

Version 0.1: young software, used in production for a small number of sites. Sites can be
created, deployed, updated, rolled back, operated with wp-cli, checked with `iwp verify` and
adopted from a classic WordPress install with `iwp import`. Tested on Rocky Linux 9 (SELinux
enforcing and disabled); see [`tests/e2e`](tests/e2e/README.md).
Operations runbook: [`docs/operations.md`](docs/operations.md).

## Commands

```
iwp validate [<site>…]                 check site files (exit 2 on problems)
iwp render <site> --out <dir>          write every generated file (quadlet, nginx, wp-config, php, timers)
iwp plugin|theme add|set|rm <site> …   edit a site file, keeping comments
iwp plugin|theme add <site> <slug> --url <zip-url> | --path <dir>
                                       add a source from elsewhere, pinned to its sha256
iwp image build <wp> <php> [--refresh-base]   build verified fpm/cli images
iwp image list | prune                        show / remove iwp images
iwp build <site>                              build a verified, read-only release (not activated yet)
iwp pin <site> [<slug>]                       record sha256 for path/git/url sources
iwp outdated <site> [--json]                  show available core/plugin/theme updates
iwp update <site>|--all [--dry-run] [--refresh-base]
                                              deploy newer wordpress.org versions, then write them into the site
                                              file (only once live) (root; run nightly by iwp-update.timer)
iwp schema                             JSON Schema for editors (also in schema/site.schema.json)
iwp nginx apply <site>                        install the nginx include, test and reload (root)
iwp nginx check <site>                        verify server blocks use the include (read-only; runs `nginx -T`)
iwp db dump <site> [--out <file>]             gzipped dump of the site database (root)
iwp db restore <site> <file> --yes            restore a dump after a safety dump (root)
iwp selinux install                           install/update the iwp SELinux policy module (root)
iwp egress apply | show                       load (or remove) the outbound filter of [egress] in iwp.toml (root) / print it
iwp alert <unit>                              mail a failed iwp unit's journal to alert_email (run by iwp-alert@.service)
iwp new <site> --domain <d>… [--base <path>] [--wordpress <v>] [--php <v>] [--salts-from <file>]
                                              create a site file (next free id) and provision the host (root)
iwp setup <site> [--salts-from <file>]        provision (or re-provision) an existing site file; idempotent (root)
iwp import <site> --from <wp-root> [--domain <d>…] [--base <path>] [--php <v>] [--new-db-user] [--id <n>] [--json]
                                              adopt a classic WordPress webroot: site file, pinned copies of custom
                                              code, DB user and secrets, uploads; never deploys (root)
iwp verify <site> [--json]                    check the live site against its manifest and core checksums
                                              (root; exit 0 clean, 3 findings, 1 check failed; daily timer)
iwp assets export <dir>                       write the files compiled into iwp (Containerfile, templates,
                                              mu-plugin, SELinux policy) to an absent or empty dir (no root)
iwp deploy <site> [--dry-run]                 build, dump DB, activate, smoke-test; auto-rollback on failure (root)
iwp rollback <site> [<release>] [--with-db --yes]   re-activate an earlier release (default: previous) (root)
iwp wp <site> <wp-cli args…>                  run wp-cli in the site's cli container (code-changing commands refused) (root)
iwp shell <site>                              shell in the site's cli container (root)
iwp cron <site>                               run due wp-cron events (used by the cron timer) (root)
iwp status [<site>] [--json]                  state, releases and image of sites (read-only)
iwp releases <site>                           list releases (read-only)
iwp gc <site>                                 remove releases and pre-deploy DB dumps beyond retention (root)
```

The commands that change the host or read site data need root (exit 2 otherwise): `nginx apply`, `db dump`, `db restore`, `selinux install`, `egress apply`, `new`, `setup`, `import`, `deploy`, `rollback`, `update`, `verify`, `wp`, `shell`, `cron`, `gc`. `assets export` needs no root.

## Install

On RPM distributions (x86_64; tested on Rocky 9 and Fedora 44), build the package and install
it. It brings in podman, nginx, the MariaDB client tools, acl, rsync and util-linux:

```
scripts/rpm.sh                         # -> dist/iwp-<version>-1.x86_64.rpm (static binary)
dnf install ./iwp-<version>-1.x86_64.rpm
```

The package installs `/usr/bin/iwp`, a commented `/etc/iwp/iwp.toml` (kept on upgrade),
`/etc/iwp/sites/` and `/var/cache/iwp/`. The SELinux tools and `nftables` are weak
dependencies; MariaDB itself (`mariadb-server`) is not pulled in. Upgrading is `dnf upgrade
./iwp-….rpm`; the sites keep running on their releases, and a deploy picks up changed units.

Without the package, copy the static binary from `scripts/build-static.sh` to
`/usr/local/bin/iwp`. The systemd units iwp generates call the path it was built for:
`/usr/bin/iwp` in the RPM, `/usr/local/bin/iwp` otherwise. Moving a host from the copied
binary to the RPM: operations.md §17.

## Host prerequisites

- podman 5 or newer
- an `nginx` group (`nginx_group` in `iwp.toml`): site base directories are `0750 root:<nginx_group>`
- mariadb client tools (`mariadb`, `mariadb-dump`)
- nginx
- `policycoreutils-python-utils` and `checkpolicy` (SELinux: `semanage`, `restorecon`, policy module build)
- a filesystem with acl support, for the tmpfiles-managed `/run/iwp/<site>` socket directories
- MariaDB listening on the podman gateway IP (set `bind-address` accordingly), so containers can reach it
- **nginx workers must be in the `nginx_group`.** The base directory is `0750 root:<nginx_group>`, so workers outside that group answer every request with 403/502 while `nginx -t`, `setup` and `deploy` all succeed. `setup` (so `new`), `nginx apply`, `deploy` (not `--dry-run`) and `import` (before any write) read the worker identity from `nginx -T` (the `user <user> [<group>]` directive, default `nginx`) and fail early if the group is missing. The usual trap is `user nginx www-users;`: the workers get gid `www-users` and only the supplementary groups of `nginx`. Fix: `usermod -aG nginx nginx && systemctl reload nginx` (use your `nginx_group` name). Never set `nginx_group` to a group that other sites' PHP runs in: that would let those sites reach this site's base directory.
- `rsync` and `setpriv` (util-linux), for `iwp import`
- optional: a working `sendmail` for `alert_email`, `nftables` for `[egress]` (operations.md §14, §15)

Global options: `--config <file>` (default `/etc/iwp/iwp.toml`, falling back to built-in defaults).

## Supply-chain checks

- Every download is HTTPS-only (on each redirect hop), size-capped at 1 GiB with gzip decoding disabled, and zip extraction rejects traversal, symlinks and duplicates.
- Core is checked against wordpress.org's SHA-1 and every webroot file outside `wp-content/` must be in the core MD5 list (only `wp-config.php` is extra).
- Plugin checksums are fetched fresh on every build; unlisted files are allowed except interpretable ones, which fail the build: `.php`, `.php0`–`.php9`, `.phtml`, `.phar`, `.inc` (case-insensitive), `.htaccess` and `.user.ini` (by file name; `.htaccess` and `.user.ini` by base name). A cached plugin zip that fails verification or contains unlisted files is refetched once before it is accepted; remaining unlisted files are reported as warnings by `iwp build`.
- Every release manifest (`.iwp-release.json`) records the image ID the core came from, a `tree_sha256` per package and language pack, and the sha256 of every regular file in the release, so it can be verified later.
- Theme zips are trust-on-first-use in `<cache_dir>/tofu.json`; a mismatch evicts the cache and refetches once before failing, and a first use never records a hash taken from a cached zip.
- `path`/`git`/`url` sources are pinned by sha256 (`iwp pin <site> <slug>` refuses while other sources are unpinned); drift fails the build.
- `iwp build` takes a per-site lock and removes stale `*.partial` dirs; the DB secret is one `KEY=value` per line (DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PREFIX).

`IWP_NET_TESTS=1` enables the live wordpress.org test.

## Site files

See `examples/simple.toml` and `examples/acme.toml`. Point your editor's TOML language server at
`schema/site.schema.json`.

## nginx integration

The generated include sets `root` and `index` itself. The operator's `server {}` block keeps
`server_name`, TLS and custom locations, adds one line, and must not set `root` or `index`
(nginx would fail with "root directive is duplicate"):

```nginx
include iwp/<site>.conf;
```

`iwp nginx check <site>` reads `nginx -T` and reports any server block for the site's domains that
does not include it.

The include denies `*.log|sql|gz|zip` under `wp-content/` (including uploads) to prevent leaking
logs and backups. Media-library archive downloads are therefore blocked (a per-site opt-in is planned).

## Development

```
scripts/check.sh                       fmt, clippy, tests, static musl build
scripts/build-static.sh                only the static musl build; prints the binary path
scripts/rpm.sh [<release>]             static build for /usr/bin/iwp and the RPM in dist/
IWP_PODMAN_TESTS=1 scripts/check.sh    also runs nginx routing and image build tests in podman
IWP_NET_TESTS=1 scripts/check.sh       also runs the live wordpress.org test
UPDATE_GOLDEN=1 cargo test --test golden   regenerate golden files (review the diff!)
```

The static build uses podman `rust:alpine` when no musl-gcc is installed.

## Acknowledgements

Developed with the assistance of large language models (Anthropic's Fable 5.1).

## License

MIT; see [`LICENSE`](LICENSE).
