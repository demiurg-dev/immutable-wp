# Packages the prebuilt static binary; build with scripts/rpm.sh (it passes iwp_version and
# the sources). The binary is linked against musl, so one package serves every x86_64 RPM
# distribution.
%global debug_package %{nil}

Name:           iwp
Version:        %{iwp_version}
Release:        %{?iwp_release}%{!?iwp_release:1}
Summary:        Immutable WordPress hosting with nginx, podman and MariaDB
License:        MIT
URL:            https://github.com/demiurg-dev/immutable-wp
Source0:        iwp
Source1:        iwp.toml
Source2:        README.md
Source3:        operations.md
Source4:        LICENSE
ExclusiveArch:  x86_64

Requires:       podman >= 5
Requires:       nginx
Requires:       /usr/bin/mariadb
Requires:       /usr/bin/mariadb-dump
Requires:       systemd
Requires:       acl
Requires:       rsync
Requires:       util-linux
# SELinux hosts (skipped cleanly when SELinux is disabled), the [egress] filter, and the
# database server when it runs on this host.
Recommends:     policycoreutils-python-utils
Recommends:     checkpolicy
Recommends:     nftables
Suggests:       mariadb-server

%description
iwp runs WordPress sites where host nginx serves static files directly and PHP runs in a
read-only php-fpm container. Plugins and themes are pinned in one file per site and mounted
read-only; deploys are atomic, smoke-tested and rolled back on failure.

%prep
cp -p %{SOURCE2} %{SOURCE3} %{SOURCE4} .

%build

%install
install -Dpm 0755 %{SOURCE0} %{buildroot}%{_bindir}/iwp
install -Dpm 0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/iwp/iwp.toml
install -d -m 0755 %{buildroot}%{_sysconfdir}/iwp/sites
install -d -m 0755 %{buildroot}%{_localstatedir}/cache/iwp

%files
%license LICENSE
%doc README.md operations.md
%{_bindir}/iwp
%dir %{_sysconfdir}/iwp
%dir %{_sysconfdir}/iwp/sites
%config(noreplace) %{_sysconfdir}/iwp/iwp.toml
%dir %{_localstatedir}/cache/iwp
