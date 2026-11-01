#!/bin/bash
# Build only below an explicit temporary root, never the caller's working directory.
set -euo pipefail
cache=$1
instance=$2
init=$3
for tool in apt-get dpkg-deb cpio gzip openssl; do
    command -v "$tool" >/dev/null || { echo "Missing WSL build tool: $tool" >&2; exit 1; }
done
[ "$(uname -m)" = x86_64 ] || { echo 'An x86_64 WSL distribution is required.' >&2; exit 1; }
work=$(mktemp -d -t pwn-college-rootfs-XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
root=$work/root
mkdir -p "$root" "$cache"
. /etc/os-release
base=$cache/base-v5-$ID-$VERSION_ID.cpio.gz
if [ ! -f "$base" ]; then
    packages=$cache/packages-$ID-$VERSION_ID
    mkdir -p "$packages/partial"
    # Empty dpkg status downloads the complete guest dependency closure without installing anything.
    apt-get -o Dir::State::status=/dev/null -o Debug::NoLocking=true \
        -o APT::Sandbox::User="$(id -un)" -o Dir::Cache::archives="$packages" \
        --download-only --assume-yes --no-install-recommends install \
        busybox-static dropbear-bin openssh-sftp-server python3.13 rsync
    mkdir -p "$root/usr/bin" "$root/usr/sbin" "$root/usr/lib" "$root/usr/lib64"
    ln -s usr/bin "$root/bin"
    ln -s usr/sbin "$root/sbin"
    ln -s usr/lib "$root/lib"
    ln -s usr/lib64 "$root/lib64"
    for package in "$packages"/*.deb; do dpkg-deb -x "$package" "$root"; done
    busybox=$(find "$root/usr" -type f -name busybox -print -quit)
    [ -n "$busybox" ] || { echo 'Guest busybox not found.' >&2; exit 1; }
    cp "$busybox" "$work/busybox"
    cp "$work/busybox" "$root/bin/busybox"
    while IFS= read -r applet; do
        # The multicall executable must not become a symlink to itself.
        [ "$applet" = busybox ] && continue
        ln -sfn busybox "$root/bin/$applet"
    done < <("$root/bin/busybox" --list)
    ln -sfn python3.13 "$root/usr/bin/python3"
    mkdir -p "$root/etc/dropbear" "$root/home/hacker/.ssh" "$root/root" \
        "$root/dev/pts" "$root/proc" "$root/sys" "$root/tmp" "$root/challenge" "$root/run"
    printf 'root:x:0:0:root:/root:/bin/sh\nhacker:x:1000:1000:hacker:/home/hacker:/bin/sh\n' > "$root/etc/passwd"
    printf 'root:x:0:\nhacker:x:1000:\n' > "$root/etc/group"
    password=$(openssl passwd -6 "$(openssl rand -hex 32)")
    printf 'root:!:0:0:99999:7:::\nhacker:%s:0:0:99999:7:::\n' "$password" > "$root/etc/shadow"
    printf 'pwn.college{practice}\n' > "$root/flag"
    chmod 600 "$root/etc/shadow"
    chmod 400 "$root/flag"
    (cd "$root"; find . -print0 | cpio --null -o -H newc --owner=0:0 --quiet | gzip -1) > "$base.part"
    mv "$base.part" "$base"
else
    (cd "$root"; gzip -dc "$base" | cpio -idmu --quiet --no-preserve-owner --no-absolute-filenames)
fi
"$root/bin/sh" -c ':'
cp "$init" "$root/init"
chmod 755 "$root" "$root/init"
cp "$instance/authorized_keys" "$root/home/hacker/.ssh/authorized_keys"
chmod 700 "$root/home/hacker/.ssh"
chmod 600 "$root/home/hacker/.ssh/authorized_keys"
loader=$(find "$root/usr/lib" -name ld-linux-x86-64.so.2 -type f -print -quit)
dropbearkey=$(find "$root/usr" -name dropbearkey -type f -print -quit)
[ -n "$loader" ] && [ -n "$dropbearkey" ] || { echo 'Guest SSH tools not found.' >&2; exit 1; }
key_command=("$loader" --library-path "$root/usr/lib/x86_64-linux-gnu" "$dropbearkey")
if [ ! -f "$instance/host_key" ]; then
    "${key_command[@]}" -t ed25519 -f "$instance/host_key" >/dev/null
fi
"${key_command[@]}" -y -f "$instance/host_key" | grep '^ssh-' > "$instance/host_key.pub"
cp "$instance/host_key" "$root/etc/dropbear/dropbear_ed25519_host_key"
chmod 600 "$root/etc/dropbear/dropbear_ed25519_host_key"
# Host kernel/symbol symlinks are intentionally absent from the guest archive.
tar --dereference -C "$(cat "$instance/challenge-path")" --exclude='./bzImage' --exclude='./vmlinux' -cf - . \
    | tar -C "$root/challenge" -xf -
(cd "$root"; find . -print0 | cpio --null -o -H newc --owner=0:0 --quiet | gzip -1) \
    > "$instance/initramfs.cpio.gz.part"
mv "$instance/initramfs.cpio.gz.part" "$instance/initramfs.cpio.gz"
