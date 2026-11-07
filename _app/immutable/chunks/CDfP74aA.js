import{$ as e,G as t,J as n,K as r,X as i,Z as a,dt as o,ft as s,j as c,k as l,l as u,m as d,ot as f,st as p}from"./CkSeWg2M.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as g}from"./k6TRNp0w.js";import{t as _}from"./DH_LefOd.js";import{t as v}from"./BzaAmULn.js";var y=c(`<p>A contributor's page: how to validate Zap against a <strong>real target</strong>. For a first
run against your own machine or a server, see <a>getting-started.md</a>.</p><p>This page covers what the hermetic suites (<a>contributing.md</a>)
can't: confirming that the generated commands
and detection probes behave on a live machine. It uses two local VMs, <strong>Alpine</strong> (<code>apk</code> and OpenRC) and <strong>Debian</strong> (<code>apt</code> and systemd), driven over SSH from a
glibc dev <code>zap</code>, by hand or through the <a>differential
harness</a>. They are VMs, not
containers, because <code>service</code>, <code>firewall</code>, <code>swap</code>, and <code>user</code> need their own
init, netfilter, and kernel, and the wetruns below are destructive.</p><h2>Prerequisites</h2><p>A hypervisor with KVM (<code>/dev/kvm</code> present). The commands below use libvirt and <code>virt-install</code>, which gives the VM a host-reachable <code>192.168.122.x</code> address so
the throwaway config works unmodified:</p><!><p>Membership in <code>libvirt</code> is what lets the unprivileged <code>virsh -c qemu:///system</code> commands below, and the differential harness, run without a password. Debian's <code>60-libvirt.rules</code> polkit rule grants <code>org.libvirt.unix.manage</code> to that group.
It is effectively root, since a member can define a VM that attaches host disks.
Grant it only on a dev machine where that's acceptable.</p><h2>The Alpine VM</h2><p>A small mixed config (an <code>apk</code> package, an OpenRC service, and a <code>file</code>) driven
through <code>detect</code>, a dry <code>apply</code>, <code>apply --wetrun</code>, and <code>apply</code> again.</p><h3>1. Bring up the VM</h3><p>Download the latest "virt" ISO <strong>into the libvirt image pool</strong>. The system
libvirt runs QEMU as <code>libvirt-qemu</code>, which can't read a <code>0750</code> home directory,
so the ISO must not live under <code>~</code>:</p><!><p>Create and install. This drops you into the serial console:</p><!><p>At <code>localhost login:</code> log in as <code>root</code> (no password) and run <code>setup-alpine</code>. The
answers that matter:</p><table><thead><tr><th>Prompt</th><th>Answer</th><th>Why</th></tr></thead><tbody><tr><td>NTP client</td><td><code>none</code></td><td>keeps <code>chrony</code> uninstalled, so the package step is a real test</td></tr><tr><td>APK mirror</td><td><code>f</code></td><td>the fastest mirror</td></tr><tr><td>user</td><td><code>ops</code></td><td>you'll add it to <code>wheel</code> next</td></tr><tr><td>SSH server</td><td><code>openssh</code></td><td></td></tr><tr><td>disk</td><td><code>sda</code>, mode <code>sys</code></td><td>a full install to disk. The disk enumerates as <code>sda</code>, not <code>vda</code>, because <code>--osinfo generic</code> uses the SATA bus. That's fine.</td></tr></tbody></table><p>Then <code>reboot</code>. It should come up as <code>alpine-zap login:</code>. From now on it's <code>sudo virsh start alpine-zap</code> and <code>sudo virsh console alpine-zap</code> (Ctrl-] exits
the console). Get its address with <code>sudo virsh domifaddr alpine-zap</code>.</p><p><code>setup-alpine</code> configures the interface for DHCP, so the address is whatever
libvirt's <code>default</code> network leases it. The differential harness expects it at <code>192.168.122.10</code>. Pin it with a DHCP host reservation for
the VM's MAC, so a lease expiry or a rebuilt network can't move it. <code>&lt;mac></code> is
the MAC column of <code>virsh -c qemu:///system domiflist alpine-zap</code>:</p><!><h3>2. Make it zap-drivable</h3><p>Zap shells out to <strong><code>sudo</code></strong> (not <code>doas</code>) and runs it <strong>non-interactively</strong> over
SSH, so the target needs <code>sudo</code> installed and a NOPASSWD sudoer. On Alpine, <code>sudo</code> lives in the <code>community</code> repo, and so does <code>chrony</code>:</p><!><p>Install your host key so Zap connects without a prompt:</p><!><h3>3. Run Zap against it</h3><p>Save this throwaway config as <code>zap.ts</code> in a directory of its own, beside a <code>package.json</code> such as <code></code>: a
config is evaluated in its project, which a <code>package.json</code> marks. It needs no
recipes. <code>host</code> and <code>user</code> are references, resolved from the operator env at
connect time:</p><!><p>Drive it, with <code>ZAP_FGRO</code> set to your <code>fgro</code> copy
(<a>install.md</a>). The <code>env</code> prefix works in every shell; in <code>bash</code> or <code>zsh</code> you can also
write the assignments inline, as <code>ALPINE_HOST=… ALPINE_USER=… zap …</code>:</p><!><p>Expected:</p><ul><li><code>detect</code> shows <code>chrony</code> absent and <code>chronyd</code> drifted
(<code>running=false, enabled=false</code>);</li><li>the dry run plans a <code>cache-update-apk</code> change (<code>apk update</code>) ahead of <code>apk add chrony</code>, <code>rc-update add chronyd default</code> and <code>rc-service chronyd start</code> (inside the <code>sh -c</code> that resets a crashed service
first), and the file;</li><li>the wetrun reports <code>applied: 4 ok, 0 failed, 0 skipped (of 4)</code>;</li><li>the <strong>final run reports <code>(no changes — converged)</code></strong>: the probes
(<code>apk info -e</code>, <code>rc-service &lt;svc> status</code>, the service's entry under <code>/etc/runlevels</code>) read
the post-apply state correctly, as the wetrun's own re-read already checked
(a <code>RESIDUAL</code> banner names anything that doesn't read converged).</li></ul><h2>The Debian VM</h2><p><code>debian-zap</code> is the apt, systemd, and ufw twin of <code>alpine-zap</code>: Debian 13's
generic cloud image, configured on first boot by cloud-init from a NoCloud seed,
at the static address <code>192.168.122.11</code>. There is no installer to click through.
The image boots straight into a configured system.</p><h3>1. Fetch and verify the cloud image</h3><!><h3>2. Write the cloud-init seed</h3><p>Three files. <code>user-data</code> creates <code>ops</code> with NOPASSWD sudo and your public key.
Zap runs <code>sudo</code> non-interactively, the same requirement as on Alpine:</p><!><p><code>meta-data</code> names the instance:</p><!><p><code>network-config</code> pins the address. A static IP keeps the configs and the harness
unmodified across rebuilds:</p><!><p>Pack them into an ISO labeled <code>cidata</code>. The label is how cloud-init finds a
NoCloud seed:</p><!><h3>3. Upload both into the <code>default</code> pool</h3><p>Upload through libvirt; don't copy into <code>/var/lib/libvirt/images/</code>. The daemon
writes the files with the ownership QEMU needs, so it works without root, and
nothing lives under <code>~</code> where <code>libvirt-qemu</code> can't read it (the Alpine ISO
gotcha):</p><!><h3>4. Create the domain</h3><!><p><strong><code>--video vga</code> is required.</strong> With <code>--graphics none</code> alone the domain gets no
video device, and this image's GRUB reboot-loops without one, never reaching the
kernel. A VGA device with no graphics backend attached is invisible but
satisfies GRUB. The serial console still works (<code>virsh console debian-zap</code>).</p><p>First boot runs cloud-init. Then <code>ssh ops@192.168.122.11 true</code> must return silently. The address is static in the
guest, but reserve it on the libvirt side too, so the DHCP pool never leases it
to another domain. <code>&lt;mac></code> comes from <code>virsh -c qemu:///system domiflist debian-zap</code>:</p><!><p>The image ships without <code>ufw</code>. A config that uses the ufw firewall backend
installs it first, with <code>zap.pkg</code>.</p><h3>5. Snapshot both VMs</h3><p>The differential harness starts every base build from a snapshot named <code>pristine</code>. It never modifies or deletes it:</p><!><h2>Gotchas</h2><p><strong><code>virt-install</code>: <code>Could not open '…/alpine-virt.iso': Permission denied</code>.</strong> The
ISO is under <code>~</code>, which <code>libvirt-qemu</code> can't read. Keep it in <code>/var/lib/libvirt/images/</code>.</p><p><strong>Every <code>virsh -c qemu:///system</code> call prompts for a password</strong> (<code>System policy prevents management of local virtualized systems</code>). Your user
isn't in the <code>libvirt</code> group, so polkit falls back to admin auth. Run <code>sudo adduser "$USER" libvirt</code>. polkit looks up group membership itself, so it
usually applies without logging in again; log out and back in if it still
prompts.</p><p><strong>Guest <code>udhcpc: no lease</code> or <code>Network unreachable</code>.</strong> A restrictive host
firewall (nftables <code>input</code> and <code>forward</code> default-drop) drops DHCP and forwarding
on <code>virbr0</code>. libvirt's own accepts live in a separate table and can't override a
sibling base-chain drop. Add <code>iifname "virbr0" accept</code> to your <code>input</code> and <code>forward</code> chains, for example <code>sudo nft insert rule inet filter input iifname "virbr0" accept</code>. That is
runtime-only, so make it durable in your firewall config.</p><p><strong>Guest <code>udhcpc: sendto: Network is down</code>.</strong> The interface is down. Run <code>ip link set eth0 up</code> before <code>udhcpc</code>. This is only relevant when testing before <code>setup-alpine</code>.</p><p><strong>Console blank after <code>virsh console</code>.</strong> The login prompt already printed; press
Enter. If <code>virsh start</code> boots a blank disk, it hangs on the unseen VGA console:
boot from the install media or check <code>virsh domblklist</code>. Don't recycle the
libvirt network while the VM runs, because it detaches the tap and <code>virbr0</code> goes <code>NO-CARRIER</code>.</p><p><strong>The Debian domain reboot-loops in GRUB right after <code>virt-install</code>.</strong> The
domain has no video device. Recreate it with <code>--video vga</code>, keeping <code>--graphics none</code>. See the Debian VM section.</p><p><strong><code>apt-get update</code> fails after a snapshot revert</strong> with <code>Signature … was created after the --not-after date</code>. The guest resumed with the
clock it had when the snapshot was taken. Set it from the host with <code>ssh ops@&lt;vm-ip> "sudo date -u -s @$(date +%s)"</code>. The differential harness does
this after every revert.</p><p><strong>The Alpine VM comes up on a different address after a rebuild or a long
shutdown.</strong> <code>setup-alpine</code> uses DHCP. Add the host reservation from the Alpine
section.</p><p><strong>The first connection after a snapshot revert takes a few seconds.</strong> The
resumed guest drops packets briefly; it is not ssh. Poll with a short ping
before timing anything.</p><p><strong>Staging a <code>remote</code> file or <code>build</code> archive relies on a target-side <code>mktemp -d '/tmp/zap-…-XXXXXX'</code>.</strong> BusyBox <code>mktemp</code> supports both <code>-d</code> and a
template ending in <code>XXXXXX</code>, so this works on stock Alpine. Confirm it on the VM
when changing an Alpine <code>tar</code> extract or <code>build</code> path.</p>`,1);function b(c,b){p(b,!0);let x=h(`testing`);d(`gk1h4h`,e=>{t(()=>{n.title=`Testing against real targets — zap`})}),g(c,{get tome(){return x},children:(t,n)=>{v(t,{children:(t,n)=>{var c=y(),d=a(c),f=e(i(d),3);o(),s(d);var p=e(d),h=e(i(p)),g=e(h,12);o(9),s(p);var v=e(p);u(v,`id`,`prerequisites`);var b=e(v,2);_(b,{lang:`sh`,dangerous_raw_html:`sudo apt install -y virtinst libvirt-daemon-system qemu-system-x86 qemu-utils
sudo systemctl enable --now libvirtd
sudo virsh net-start default<span class="token_punctuation">;</span> sudo virsh net-autostart default   <span class="token_comment"># NAT network up</span>
sudo adduser <span class="token_string">"<span class="token_variable">$USER</span>"</span> libvirt   <span class="token_comment"># reach qemu:///system without a polkit password prompt</span>`});var x=e(b,2);u(x,`id`,`the-alpine-vm`);var S=e(x,2);u(S,`id`,`1-bring-up-the-vm`);var C=e(S,2);_(C,{lang:`sh`,dangerous_raw_html:`base=https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64
iso=<span class="token_command_substitution"><span class="token_punctuation">$(</span>curl -s <span class="token_variable">$base</span>/ <span class="token_operator">|</span> grep -o <span class="token_string">'alpine-virt-[0-9.]*-x86_64.iso'</span> <span class="token_operator">|</span> sort -u <span class="token_operator">|</span> head -<span class="token_number">1</span><span class="token_punctuation">)</span></span>
sudo curl -fL -o /var/lib/libvirt/images/alpine-virt.iso <span class="token_string">"<span class="token_variable">$base</span>/<span class="token_variable">$iso</span>"</span>`});var w=e(C,2);_(w,{lang:`sh`,dangerous_raw_html:`sudo virt-install --name alpine-zap --memory <span class="token_number">1024</span> --vcpus <span class="token_number">2</span> \\
  --disk size=<span class="token_number">4</span><span class="token_punctuation">,</span>format=qcow2 \\
  --cdrom /var/lib/libvirt/images/alpine-virt.iso \\
  --osinfo generic --network network=default \\
  --graphics none --console pty<span class="token_punctuation">,</span>target_type=serial`});var T=e(w,5);_(T,{lang:`sh`,dangerous_raw_html:`virsh -c qemu:///system net-update default add ip-dhcp-host \\
  <span class="token_string">"&lt;host mac='&lt;mac>' name='alpine-zap' ip='192.168.122.10'/>"</span> --live --config`});var E=e(T);u(E,`id`,`2-make-it-zap-drivable`);var D=e(E,2);_(D,{lang:`sh`,dangerous_raw_html:`<span class="token_comment"># in the VM, as root:</span>
setup-apkrepos -c -f          <span class="token_comment"># enable the community repo + fastest mirror</span>
apk update <span class="token_operator">&amp;&amp;</span> apk add sudo
adduser ops wheel
<span class="token_builtin">echo</span> <span class="token_string">'%wheel ALL=(ALL) NOPASSWD: ALL'</span> <span class="token_operator">></span> /etc/sudoers.d/wheel
chmod <span class="token_number">0440</span> /etc/sudoers.d/wheel`});var O=e(D,2);_(O,{lang:`sh`,dangerous_raw_html:`<span class="token_comment"># on the host:</span>
ssh-copy-id ops@<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span>
ssh ops@<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> <span class="token_boolean">true</span>          <span class="token_comment"># must return silently</span>`});var k=e(O);u(k,`id`,`3-run-zap-against-it`);var A=e(k),j=e(i(A),5);j.textContent=`{"name": "zap-alpine-probe", "type": "module"}`,o(7),s(A);var M=e(A);_(M,{lang:`ts`,dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
  zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>
    host<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'ALPINE_HOST'</span><span class="token_punctuation">),</span>
    user<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'ALPINE_USER'</span><span class="token_punctuation">),</span>
    package_manager<span class="token_operator">:</span> <span class="token_string">"apk"</span><span class="token_punctuation">,</span>
    service_manager<span class="token_operator">:</span> <span class="token_string">"openrc"</span><span class="token_punctuation">,</span>
  <span class="token_punctuation">});</span>
  zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span> id<span class="token_operator">:</span> <span class="token_string">"chrony"</span><span class="token_punctuation">,</span> name<span class="token_operator">:</span> <span class="token_string">"chrony"</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span> apk<span class="token_operator">:</span> <span class="token_string">"chrony"</span> <span class="token_punctuation">}</span> <span class="token_punctuation">});</span>
  zap<span class="token_punctuation">.</span><span class="token_function">service</span><span class="token_punctuation">({</span>
    id<span class="token_operator">:</span> <span class="token_string">"chronyd"</span><span class="token_punctuation">,</span>
    name<span class="token_operator">:</span> <span class="token_string">"chronyd"</span><span class="token_punctuation">,</span>
    service<span class="token_operator">:</span> <span class="token_string">"chronyd"</span><span class="token_punctuation">,</span>
    enabled<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span>
    running<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span>
    depends_on<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">"chrony"</span><span class="token_punctuation">],</span>
  <span class="token_punctuation">});</span>
  zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
    id<span class="token_operator">:</span> <span class="token_string">"zap-probe-file"</span><span class="token_punctuation">,</span>
    name<span class="token_operator">:</span> <span class="token_string">"zap probe file"</span><span class="token_punctuation">,</span>
    path<span class="token_operator">:</span> <span class="token_string">"/etc/zap-alpine-probe"</span><span class="token_punctuation">,</span>
    content<span class="token_operator">:</span> <span class="token_punctuation">{</span> type<span class="token_operator">:</span> <span class="token_string">"inline"</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> <span class="token_string">"zap alpine validation\\n"</span> <span class="token_punctuation">},</span>
    mode<span class="token_operator">:</span> <span class="token_string">"644"</span><span class="token_punctuation">,</span>
  <span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>`});var N=e(M),P=e(i(N),5);o(9),s(N);var F=e(N);_(F,{lang:`sh`,dangerous_raw_html:`env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap lock            <span class="token_comment"># pin the fgro build ZAP_FGRO names</span>
env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap detect          <span class="token_comment"># probe sanity</span>
env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap apply           <span class="token_comment"># dry-run: see the plan</span>
env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap apply --wetrun  <span class="token_comment"># converge</span>
env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap apply           <span class="token_comment"># idempotency re-check</span>`});var I=e(F,3);u(I,`id`,`the-debian-vm`);var L=e(I,2);u(L,`id`,`1-fetch-and-verify-the-cloud-image`);var R=e(L);_(R,{lang:`sh`,dangerous_raw_html:`base=https://cloud.debian.org/images/cloud/trixie/latest
curl -fLO <span class="token_variable">$base</span>/debian-<span class="token_number">13</span>-genericcloud-amd64.qcow2
curl -fLO <span class="token_variable">$base</span>/SHA512SUMS
sha512sum --ignore-missing -c SHA512SUMS   <span class="token_comment"># must print "debian-13-genericcloud-amd64.qcow2: OK"</span>
qemu-img resize debian-<span class="token_number">13</span>-genericcloud-amd64.qcow2 8G   <span class="token_comment"># cloud-init grows / on first boot</span>`});var z=e(R);u(z,`id`,`2-write-the-cloud-init-seed`);var B=e(z,2);_(B,{lang:`yaml`,content:`#cloud-config
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
package_update: false`});var V=e(B,2);_(V,{lang:`yaml`,content:`instance-id: debian-zap
local-hostname: debian-zap`});var H=e(V,2);_(H,{lang:`yaml`,content:`version: 2
ethernets:
  primary:
    match:
      name: "en*"
    addresses: [192.168.122.11/24]
    routes:
      - to: default
        via: 192.168.122.1
    nameservers:
      addresses: [192.168.122.1]`});var U=e(H,2);_(U,{lang:`sh`,content:`xorriso -as mkisofs -output debian-zap-seed.iso -volid cidata -joliet -rock \\
  user-data meta-data network-config`});var W=e(U);u(W,`id`,`3-upload-both-into-the-default-pool`);var G=e(W,2);_(G,{lang:`sh`,dangerous_raw_html:`v=<span class="token_string">"virsh -c qemu:///system"</span>
<span class="token_variable">$v</span> vol-create-as default debian-zap.qcow2 8G --format qcow2
<span class="token_variable">$v</span> vol-upload --pool default debian-zap.qcow2 debian-<span class="token_number">13</span>-genericcloud-amd64.qcow2
<span class="token_variable">$v</span> vol-create-as default debian-zap-seed.iso <span class="token_command_substitution"><span class="token_punctuation">$(</span>stat -c %s debian-zap-seed.iso<span class="token_punctuation">)</span></span> --format raw
<span class="token_variable">$v</span> vol-upload --pool default debian-zap-seed.iso debian-zap-seed.iso`});var K=e(G);u(K,`id`,`4-create-the-domain`);var q=e(K);_(q,{lang:`sh`,dangerous_raw_html:`virt-install --connect qemu:///system --name debian-zap --memory <span class="token_number">1024</span> --vcpus <span class="token_number">2</span> \\
  --disk vol=default/debian-zap.qcow2<span class="token_punctuation">,</span>bus=virtio \\
  --disk vol=default/debian-zap-seed.iso<span class="token_punctuation">,</span>device=cdrom \\
  --import --osinfo debian13 --network network=default \\
  --graphics none --video vga --console pty<span class="token_punctuation">,</span>target_type=serial --noautoconsole`});var J=e(q,3);_(J,{lang:`sh`,dangerous_raw_html:`virsh -c qemu:///system net-update default add ip-dhcp-host \\
  <span class="token_string">"&lt;host mac='&lt;mac>' name='debian-zap' ip='192.168.122.11'/>"</span> --live --config`});var Y=e(J,2);u(Y,`id`,`5-snapshot-both-vms`);var X=e(Y,2);_(X,{lang:`sh`,content:`virsh -c qemu:///system snapshot-create-as debian-zap pristine
virsh -c qemu:///system snapshot-create-as alpine-zap pristine`});var Z=e(X);u(Z,`id`,`gotchas`),o(10),r((e,t,n,r)=>{u(f,`href`,e),u(h,`href`,t),u(g,`href`,n),u(P,`href`,r)},[()=>m(`docs/getting-started`),()=>m(`docs/contributing#the-hermetic-suites`),()=>m(`docs/differential`),()=>m(`docs/install#getting-fgro`)]),l(t,c)},$$slots:{default:!0}})},$$slots:{default:!0}}),f()}export{b as t};