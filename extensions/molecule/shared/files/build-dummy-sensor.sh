#!/bin/sh
# Build a dummy falcon-sensor package that holds the falconctl stub and a
# falcon-sensor systemd unit. It builds a .deb where dpkg-deb exists, else
# an .rpm with rpmbuild.
#
# usage: build-dummy-sensor.sh <version> <source dir> <output dir>
set -eu

version=$1
src=$2
out=$3
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$out"

stage() {
    root=$1
    mkdir -p "$root/opt/CrowdStrike"
    { echo "#!/usr/bin/python3"; cat "$src/falconctl.py"; } > "$root/opt/CrowdStrike/falconctl"
    chmod 0755 "$root/opt/CrowdStrike/falconctl"
    install -D -m 0644 "$src/falcon-sensor.service" "$root/usr/lib/systemd/system/falcon-sensor.service"
    echo "$version" > "$root/opt/CrowdStrike/VERSION"
}

if command -v dpkg-deb >/dev/null 2>&1; then
    root="$work/root"
    stage "$root"
    mkdir -p "$root/DEBIAN"
    cat > "$root/DEBIAN/control" <<EOF
Package: falcon-sensor
Version: $version
Architecture: all
Maintainer: crowdstrike.falcon molecule tests <noreply@example.com>
Description: Dummy falcon-sensor package for the molecule tests
EOF
    dpkg-deb --root-owner-group --build "$root" "$out/falcon-sensor-$version.deb" >/dev/null
else
    mkdir -p "$work/SPECS" "$work/BUILDROOT"
    cat > "$work/SPECS/falcon-sensor.spec" <<EOF
Name: falcon-sensor
Version: $version
Release: 1
Summary: Dummy falcon-sensor package for the molecule tests
License: GPL-3.0-or-later
BuildArch: noarch
AutoReqProv: no

%description
Dummy falcon-sensor package for the molecule tests.

%install
mkdir -p %{buildroot}
cp -a $work/stage/. %{buildroot}/

%files
/opt/CrowdStrike/falconctl
/opt/CrowdStrike/VERSION
/usr/lib/systemd/system/falcon-sensor.service
EOF
    stage "$work/stage"
    rpmbuild --quiet --define "_topdir $work" -bb "$work/SPECS/falcon-sensor.spec"
    rpm="$out/falcon-sensor-$version.rpm"
    cp "$work"/RPMS/noarch/falcon-sensor-"$version"-1.noarch.rpm "$rpm"

    # dnf checks the signature of local packages too, so sign the package
    # with a throwaway key and trust that key in the rpm database.
    export GNUPGHOME="$src/gnupg"
    key="falcon-molecule-test@example.com"
    if [ ! -d "$GNUPGHOME" ]; then
        mkdir -m 0700 "$GNUPGHOME"
        gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$key" rsa3072 sign never
        gpg --armor --export "$key" > "$GNUPGHOME/public.asc"
        rpm --import "$GNUPGHOME/public.asc"
    fi
    rpmsign --define "_gpg_name $key" --addsign "$rpm" >/dev/null
fi
