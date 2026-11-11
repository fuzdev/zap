# Testing against real targets

A contributor's page: how to validate Zap against a **real target**. For a first
run against your own machine or a server, see
[getting-started.md](./getting-started.md).

This page covers what the hermetic suites ([contributing.md](./contributing.md#the-hermetic-suites))
can't: confirming that the generated commands
and detection probes behave on a live machine. It uses two local VMs, **Alpine**
(`apk` and OpenRC) and **Debian** (`apt` and systemd), driven over SSH from a
glibc dev `zap`, by hand or through the [differential
harness](./differential.md). They are VMs, not
containers, because `service`, `firewall`, `swap`, and `user` need their own
init, netfilter, and kernel, and the wetruns below are destructive.

## Prerequisites

A hypervisor with KVM (`/dev/kvm` present). The commands below use libvirt and
`virt-install`, which gives the VM a host-reachable `192.168.122.x` address so
the throwaway config works unmodified:

```sh
sudo apt install -y virtinst libvirt-daemon-system qemu-system-x86 qemu-utils
sudo systemctl enable --now libvirtd
sudo virsh net-start default; sudo virsh net-autostart default   # NAT network up
sudo adduser "$USER" libvirt   # reach qemu:///system without a polkit password prompt
```

Membership in `libvirt` is what lets the unprivileged `virsh -c qemu:///system`
commands below, and the differential harness, run without a password. Debian's
`60-libvirt.rules` polkit rule grants `org.libvirt.unix.manage` to that group.
It is effectively root, since a member can define a VM that attaches host disks.
Grant it only on a dev machine where that's acceptable.

## The Alpine VM

A small mixed config (an `apk` package, an OpenRC service, and a `file`) driven
through `detect`, a dry `apply`, `apply --wetrun`, and `apply` again.

### 1. Bring up the VM

Download the latest "virt" ISO **into the libvirt image pool**. The system
libvirt runs QEMU as `libvirt-qemu`, which can't read a `0750` home directory,
so the ISO must not live under `~`:

```sh
base=https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64
iso=$(curl -s $base/ | grep -o 'alpine-virt-[0-9.]*-x86_64.iso' | sort -u | head -1)
sudo curl -fL -o /var/lib/libvirt/images/alpine-virt.iso "$base/$iso"
```

Create and install. This drops you into the serial console:

```sh
sudo virt-install --name alpine-zap --memory 1024 --vcpus 2 \
  --disk size=4,format=qcow2 \
  --cdrom /var/lib/libvirt/images/alpine-virt.iso \
  --osinfo generic --network network=default \
  --graphics none --console pty,target_type=serial
```

At `localhost login:` log in as `root` (no password) and run `setup-alpine`. The
answers that matter:

| Prompt | Answer | Why |
|---|---|---|
| NTP client | `none` | keeps `chrony` uninstalled, so the package step is a real test |
| APK mirror | `f` | the fastest mirror |
| user | `ops` | you'll add it to `wheel` next |
| SSH server | `openssh` | |
| disk | `sda`, mode `sys` | a full install to disk. The disk enumerates as `sda`, not `vda`, because `--osinfo generic` uses the SATA bus. That's fine. |

Then `reboot`. It should come up as `alpine-zap login:`. From now on it's
`sudo virsh start alpine-zap` and `sudo virsh console alpine-zap` (Ctrl-] exits
the console). Get its address with `sudo virsh domifaddr alpine-zap`.

`setup-alpine` configures the interface for DHCP, so the address is whatever
libvirt's `default` network leases it. The differential harness expects it at
`192.168.122.10`. Pin it with a DHCP host reservation for
the VM's MAC, so a lease expiry or a rebuilt network can't move it. `<mac>` is
the MAC column of `virsh -c qemu:///system domiflist alpine-zap`:

```sh
virsh -c qemu:///system net-update default add ip-dhcp-host \
  "<host mac='<mac>' name='alpine-zap' ip='192.168.122.10'/>" --live --config
```

### 2. Make it zap-drivable

Zap shells out to **`sudo`** (not `doas`) and runs it **non-interactively** over
SSH, so the target needs `sudo` installed and a NOPASSWD sudoer. On Alpine,
`sudo` lives in the `community` repo, and so does `chrony`:

```sh
# in the VM, as root:
setup-apkrepos -c -f          # enable the community repo + fastest mirror
apk update && apk add sudo
adduser ops wheel
echo '%wheel ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/wheel
chmod 0440 /etc/sudoers.d/wheel
```

Install your host key so Zap connects without a prompt:

```sh
# on the host:
ssh-copy-id ops@<vm-ip>
ssh ops@<vm-ip> true          # must return silently
```

### 3. Run Zap against it

Save this throwaway config as `zap.ts` in a directory of its own, beside a
`package.json` such as `{"name": "zap-alpine-probe", "type": "module"}`: a
config is evaluated in its project, which a `package.json` marks. It needs no
recipes. `host` and `user` are references, resolved from the operator env at
connect time:

```ts
// zap.ts
export default (zap) => {
  zap.target({
    host: zap.env('ALPINE_HOST'),
    user: zap.env('ALPINE_USER'),
    package_manager: "apk",
    service_manager: "openrc",
  });
  zap.pkg({ id: "chrony", name: "chrony", from: { apk: "chrony" } });
  zap.service({
    id: "chronyd",
    name: "chronyd",
    service: "chronyd",
    enabled: true,
    running: true,
    depends_on: ["chrony"],
  });
  zap.file({
    id: "zap-probe-file",
    name: "zap probe file",
    path: "/etc/zap-alpine-probe",
    content: { type: "inline", content: "zap alpine validation\n" },
    mode: "644",
  });
};
```

Drive it, with `ZAP_FGRO` set to your `fgro` copy
([install.md](./install.md#getting-fgro)). The `env` prefix works in every shell; in `bash` or `zsh` you can also
write the assignments inline, as `ALPINE_HOST=… ALPINE_USER=… zap …`:

```sh
env ALPINE_HOST=<vm-ip> ALPINE_USER=ops zap lock            # pin the fgro build ZAP_FGRO names
env ALPINE_HOST=<vm-ip> ALPINE_USER=ops zap detect          # probe sanity
env ALPINE_HOST=<vm-ip> ALPINE_USER=ops zap apply           # dry-run: see the plan
env ALPINE_HOST=<vm-ip> ALPINE_USER=ops zap apply --wetrun  # converge
env ALPINE_HOST=<vm-ip> ALPINE_USER=ops zap apply           # idempotency re-check
```

Expected:

- `detect` shows `chrony` absent and `chronyd` drifted
  (`running=false, enabled=false`);
- the dry run plans a `cache-update-apk` change (`apk update`) ahead of
  `apk add chrony`, `rc-update add chronyd default` and
  `rc-service chronyd start` (inside the `sh -c` that resets a crashed service
  first), and the file;
- the wetrun reports `applied: 4 ok, 0 failed, 0 skipped (of 4)` and closes
  with `converged <vm-ip> in <time>, the re-detect included`;
- the **final run reports `(no changes — converged)`**: the probes
  (`apk info -e`, `rc-service <svc> status`, the service's entry under
  `/etc/runlevels`) read
  the post-apply state correctly, as the wetrun's own re-read already checked
  (a `RESIDUAL` banner names anything that doesn't read converged).

## The Debian VM

`debian-zap` is the apt, systemd, and ufw twin of `alpine-zap`: Debian 13's
generic cloud image, configured on first boot by cloud-init from a NoCloud seed,
at the static address `192.168.122.11`. There is no installer to click through.
The image boots straight into a configured system.

### 1. Fetch and verify the cloud image

```sh
base=https://cloud.debian.org/images/cloud/trixie/latest
curl -fLO $base/debian-13-genericcloud-amd64.qcow2
curl -fLO $base/SHA512SUMS
sha512sum --ignore-missing -c SHA512SUMS   # must print "debian-13-genericcloud-amd64.qcow2: OK"
qemu-img resize debian-13-genericcloud-amd64.qcow2 8G   # cloud-init grows / on first boot
```

### 2. Write the cloud-init seed

Three files. `user-data` creates `ops` with NOPASSWD sudo and your public key.
Zap runs `sudo` non-interactively, the same requirement as on Alpine:

```yaml
#cloud-config
hostname: debian-zap
users:
  - name: ops
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys:
      - ssh-ed25519 AAAA… you@host
ssh_pwauth: false
package_update: false
```

`meta-data` names the instance:

```yaml
instance-id: debian-zap
local-hostname: debian-zap
```

`network-config` pins the address. A static IP keeps the configs and the harness
unmodified across rebuilds:

```yaml
version: 2
ethernets:
  primary:
    match:
      name: "en*"
    addresses: [192.168.122.11/24]
    routes:
      - to: default
        via: 192.168.122.1
    nameservers:
      addresses: [192.168.122.1]
```

Pack them into an ISO labeled `cidata`. The label is how cloud-init finds a
NoCloud seed:

```sh
xorriso -as mkisofs -output debian-zap-seed.iso -volid cidata -joliet -rock \
  user-data meta-data network-config
```

### 3. Upload both into the `default` pool

Upload through libvirt; don't copy into `/var/lib/libvirt/images/`. The daemon
writes the files with the ownership QEMU needs, so it works without root, and
nothing lives under `~` where `libvirt-qemu` can't read it (the Alpine ISO
gotcha):

```sh
v="virsh -c qemu:///system"
$v vol-create-as default debian-zap.qcow2 8G --format qcow2
$v vol-upload --pool default debian-zap.qcow2 debian-13-genericcloud-amd64.qcow2
$v vol-create-as default debian-zap-seed.iso $(stat -c %s debian-zap-seed.iso) --format raw
$v vol-upload --pool default debian-zap-seed.iso debian-zap-seed.iso
```

### 4. Create the domain

```sh
virt-install --connect qemu:///system --name debian-zap --memory 1024 --vcpus 2 \
  --disk vol=default/debian-zap.qcow2,bus=virtio \
  --disk vol=default/debian-zap-seed.iso,device=cdrom \
  --import --osinfo debian13 --network network=default \
  --graphics none --video vga --console pty,target_type=serial --noautoconsole
```

**`--video vga` is required.** With `--graphics none` alone the domain gets no
video device, and this image's GRUB reboot-loops without one, never reaching the
kernel. A VGA device with no graphics backend attached is invisible but
satisfies GRUB. The serial console still works (`virsh console debian-zap`).

First boot runs cloud-init. Then
`ssh ops@192.168.122.11 true` must return silently. The address is static in the
guest, but reserve it on the libvirt side too, so the DHCP pool never leases it
to another domain. `<mac>` comes from
`virsh -c qemu:///system domiflist debian-zap`:

```sh
virsh -c qemu:///system net-update default add ip-dhcp-host \
  "<host mac='<mac>' name='debian-zap' ip='192.168.122.11'/>" --live --config
```

The image ships without `ufw`. A config that uses the ufw firewall backend
installs it first, with `zap.pkg`.

### 5. Snapshot both VMs

The differential harness starts every base build from a snapshot named
`pristine`. It never modifies or deletes it:

```sh
virsh -c qemu:///system snapshot-create-as debian-zap pristine
virsh -c qemu:///system snapshot-create-as alpine-zap pristine
```

## Gotchas

**`virt-install`: `Could not open '…/alpine-virt.iso': Permission denied`.** The
ISO is under `~`, which `libvirt-qemu` can't read. Keep it in
`/var/lib/libvirt/images/`.

**Every `virsh -c qemu:///system` call prompts for a password**
(`System policy prevents management of local virtualized systems`). Your user
isn't in the `libvirt` group, so polkit falls back to admin auth. Run
`sudo adduser "$USER" libvirt`. polkit looks up group membership itself, so it
usually applies without logging in again; log out and back in if it still
prompts.

**Guest `udhcpc: no lease` or `Network unreachable`.** A restrictive host
firewall (nftables `input` and `forward` default-drop) drops DHCP and forwarding
on `virbr0`. libvirt's own accepts live in a separate table and can't override a
sibling base-chain drop. Add `iifname "virbr0" accept` to your `input` and
`forward` chains, for example
`sudo nft insert rule inet filter input iifname "virbr0" accept`. That is
runtime-only, so make it durable in your firewall config.

**Guest `udhcpc: sendto: Network is down`.** The interface is down. Run
`ip link set eth0 up` before `udhcpc`. This is only relevant when testing before
`setup-alpine`.

**Console blank after `virsh console`.** The login prompt already printed; press
Enter. If `virsh start` boots a blank disk, it hangs on the unseen VGA console:
boot from the install media or check `virsh domblklist`. Don't recycle the
libvirt network while the VM runs, because it detaches the tap and `virbr0` goes
`NO-CARRIER`.

**The Debian domain reboot-loops in GRUB right after `virt-install`.** The
domain has no video device. Recreate it with `--video vga`, keeping
`--graphics none`. See the Debian VM section.

**`apt-get update` fails after a snapshot revert** with
`Signature … was created after the --not-after date`. The guest resumed with the
clock it had when the snapshot was taken. Set it from the host with
`ssh ops@<vm-ip> "sudo date -u -s @$(date +%s)"`. The differential harness does
this after every revert.

**The Alpine VM comes up on a different address after a rebuild or a long
shutdown.** `setup-alpine` uses DHCP. Add the host reservation from the Alpine
section.

**The first connection after a snapshot revert takes a few seconds.** The
resumed guest drops packets briefly; it is not ssh. Poll with a short ping
before timing anything.

**Staging a `remote` file or `build` archive relies on a target-side
`mktemp -d '/tmp/zap-…-XXXXXX'`.** BusyBox `mktemp` supports both `-d` and a
template ending in `XXXXXX`, so this works on stock Alpine. Confirm it on the VM
when changing an Alpine `tar` extract or `build` path.
