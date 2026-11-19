import{K as e,Q as t,Y as ee,Z as n,ct as r,et as i,j as a,k as te,l as o,lt as s,m as ne,mt as c,pt as l,q as re}from"./DGWDGHf_.js";import{t as u}from"./hWJyV7ZK.js";import{t as d}from"./xlPESoVd.js";import{t as f}from"./B0EoXBDb.js";import{n as p}from"./BkOGAUkd.js";import{t as m}from"./DCLBpiTL.js";import"./CMLJYHjj.js";var ie=a(`<p>A contributor's page: how to validate Zap against a <strong>real target</strong> <a>getting-started.md</a>.</p><p>This page covers what the hermetic suites (<a>contributing.md</a>)
can't: confirming that the generated commands
and detection probes behave on a live machine. It uses two local VMs, <strong>Alpine</strong> <code>apk</code> and OpenRC) and <strong>Debian</strong> (<code>apt</code> and systemd), driven over SSH from a
glibc dev <code>zap</code>, by hand or through the <a>differential
harness</a>. They are VMs, not
containers, because <code>service</code>, <code>firewall</code>, <code>swap</code>, and <code>user</code> need their own
init, netfilter, and kernel, and the wetruns below are destructive.</p><h2>Prerequisites</h2><p>A hypervisor with KVM (<code>/dev/kvm</code> <code>virt-install</code>, which gives the VM a host-reachable <code>192.168.122.x</code> address so
the throwaway config works unmodified:</p><!><p>Membership in <code>libvirt</code> is what lets the unprivileged <code>virsh -c qemu:///system</code> <code>60-libvirt.rules</code> polkit rule grants <code>org.libvirt.unix.manage</code> to that group.
It is effectively root, since a member can define a VM that attaches host disks.
Grant it only on a dev machine where that's acceptable.</p><h2>The Alpine VM</h2><p>A small mixed config (an <code>apk</code> package, an OpenRC service, and a <code>file</code>) driven
through <code>detect</code>, a dry <code>apply</code>, <code>apply --wetrun</code>, and <code>apply</code> again.</p><h3>1. Bring up the VM</h3><p>Download the latest "virt" ISO <strong>into the libvirt image pool</strong>. The system
libvirt runs QEMU as <code>libvirt-qemu</code>, which can't read a <code>0750</code> home directory,
so the ISO must not live under <code>~</code>:</p><!><p>Create and install. This drops you into the serial console:</p><!><p>At <code>localhost login:</code> log in as <code>root</code> (no password) and run <code>setup-alpine</code>. The
answers that matter:</p><table><thead><tr><th>Prompt</th><th>Answer</th><th>Why</th></tr></thead><tbody><tr><td>NTP client</td><td><code>none</code></td><td>keeps <code>chrony</code> uninstalled, so the package step is a real test</td></tr><tr><td>APK mirror</td><td><code>f</code></td><td>the fastest mirror</td></tr><tr><td>user</td><td><code>ops</code></td><td>you'll add it to <code>wheel</code> next</td></tr><tr><td>SSH server</td><td><code>openssh</code></td><td></td></tr><tr><td>disk</td><td><code>sda</code>, mode <code>sys</code></td><td>a full install to disk. The disk enumerates as <code>sda</code>, not <code>vda</code>, because <code>--osinfo generic</code> uses the SATA bus. That's fine.</td></tr></tbody></table><p>Then <code>reboot</code>. It should come up as <code>alpine-zap login:</code> <code>sudo virsh start alpine-zap</code> and <code>sudo virsh console alpine-zap</code> (Ctrl-] exits
the console). Get its address with <code>sudo virsh domifaddr alpine-zap</code>.</p><p><code>setup-alpine</code> configures the interface for DHCP, so the address is whatever
libvirt's <code>default</code> <code>192.168.122.10</code>. Pin it with a DHCP host reservation for
the VM's MAC, so a lease expiry or a rebuilt network can't move it. <code>&lt;mac></code> is
the MAC column of <code>virsh -c qemu:///system domiflist alpine-zap</code>:</p><!><h3>2. Make it zap-drivable</h3><p>Zap shells out to <strong><code>sudo</code></strong> (not <code>doas</code>) and runs it <strong>non-interactively</strong> over
SSH, so the target needs <code>sudo</code> <code>sudo</code> lives in the <code>community</code> repo, and so does <code>chrony</code>:</p><!><p>Install your host key so Zap connects without a prompt:</p><!><h3>3. Run Zap against it</h3><p>Save this throwaway config as <code>zap.ts</code> <code>package.json</code> such as <code></code>: a
config is evaluated in its project, which a <code>package.json</code> marks. It needs no
recipes. <code>host</code> and <code>user</code> are references, resolved from the operator env at
connect time:</p><!><p>Drive it, with <code>ZAP_FGRO</code> set to your <code>fgro</code> copy
(<a>install.md</a>). The <code>env</code> prefix works in every shell; in <code>bash</code> or <code>zsh</code> you can also
write the assignments inline, as <code>ALPINE_HOST=… ALPINE_USER=… zap …</code>:</p><!><p>Expected:</p><ul><li><code>detect</code> shows <code>chrony</code> absent and <code>chronyd</code> drifted
(<code>running=false, enabled=false</code>);</li><li>the dry run plans a <code>cache-update-apk</code> change (<code>apk update</code> <code>apk add chrony</code>, <code>rc-update add chronyd default</code> <code>rc-service chronyd start</code> (inside the <code>sh -c</code> that resets a crashed service
first), and the file;</li><li>the wetrun reports <code>applied: 4 ok, 0 failed, 0 skipped (of 4)</code> and closes
with <code>converged &lt;vm-ip> in &lt;time>, the re-detect included</code>;</li><li>the <strong>final run reports <code>(no changes — converged)</code></strong>: the probes
(<code>apk info -e</code>, <code>rc-service &lt;svc> status</code> <code>/etc/runlevels</code>) read
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
satisfies GRUB. The serial console still works (<code>virsh console debian-zap</code>).</p><p> <code>ssh ops@192.168.122.11 true</code> must return silently. The address is static in the
guest, but reserve it on the libvirt side too, so the DHCP pool never leases it
to another domain. <code>&lt;mac></code> <code>virsh -c qemu:///system domiflist debian-zap</code>:</p><!><p>The image ships without <code>ufw</code>. A config that uses the ufw firewall backend
installs it first, with <code>zap.pkg</code>.</p><h3>5. Snapshot both VMs</h3><p> <code>pristine</code>. It never modifies or deletes it:</p><!><h2>Gotchas</h2><p><strong><code>virt-install</code>: <code>Could not open '…/alpine-virt.iso': Permission denied</code>.</strong> The
ISO is under <code>~</code>, which <code>libvirt-qemu</code> <code>/var/lib/libvirt/images/</code>.</p><p><strong>Every <code>virsh -c qemu:///system</code> call prompts for a password</strong> <code>System policy prevents management of local virtualized systems</code>). Your user
isn't in the <code>libvirt</code> <code>sudo adduser "$USER" libvirt</code>. polkit looks up group membership itself, so it
usually applies without logging in again; log out and back in if it still
prompts.</p><p><strong>Guest <code>udhcpc: no lease</code> or <code>Network unreachable</code>.</strong> A restrictive host
firewall (nftables <code>input</code> and <code>forward</code> default-drop) drops DHCP and forwarding
on <code>virbr0</code>. libvirt's own accepts live in a separate table and can't override a
sibling base-chain drop. Add <code>iifname "virbr0" accept</code> to your <code>input</code> <code>forward</code> <code>sudo nft insert rule inet filter input iifname "virbr0" accept</code>. That is
runtime-only, so make it durable in your firewall config.</p><p><strong>Guest <code>udhcpc: sendto: Network is down</code>.</strong> <code>ip link set eth0 up</code> before <code>udhcpc</code> <code>setup-alpine</code>.</p><p><strong>Console blank after <code>virsh console</code>.</strong> The login prompt already printed; press
Enter. If <code>virsh start</code> boots a blank disk, it hangs on the unseen VGA console:
boot from the install media or check <code>virsh domblklist</code>. Don't recycle the
libvirt network while the VM runs, because it detaches the tap and <code>virbr0</code> <code>NO-CARRIER</code>.</p><p><strong>The Debian domain reboot-loops in GRUB right after <code>virt-install</code>.</strong> The
domain has no video device. Recreate it with <code>--video vga</code> <code>--graphics none</code>. See the Debian VM section.</p><p><strong><code>apt-get update</code> fails after a snapshot revert</strong> <code>Signature … was created after the --not-after date</code> <code>ssh ops@&lt;vm-ip> "sudo date -u -s @$(date +%s)"</code>. The differential harness does
this after every revert.</p><p><strong>The Alpine VM comes up on a different address after a rebuild or a long
shutdown.</strong> <code>setup-alpine</code> uses DHCP. Add the host reservation from the Alpine
section.</p><p><strong>The first connection after a snapshot revert takes a few seconds.</strong> The
resumed guest drops packets briefly; it is not ssh. Poll with a short ping
before timing anything.</p><p><strong>Staging a <code>remote</code> file or <code>build</code> <code>mktemp -d '/tmp/zap-…-XXXXXX'</code>.</strong> BusyBox <code>mktemp</code> supports both <code>-d</code> and a
template ending in <code>XXXXXX</code>, so this works on stock Alpine. Confirm it on the VM
when changing an Alpine <code>tar</code> extract or <code>build</code> path.</p>`,1);function h(a,h){s(h,!0);let g=p(`testing`);ne(`gk1h4h`,t=>{e(()=>{ee.title=`Testing against real targets — zap`})}),f(a,{get tome(){return g},children:(e,ee)=>{d(e,{children:(e,ee)=>{var r=ie(),a=t(r),s=i(n(a),2);s.nodeValue=`. For a first
run against your own machine or a server, see
`;var ne=i(s);l(),c(a);var d=i(a),f=i(n(d)),p=i(f,3);p.nodeValue=`
(`;var h=i(p,9);l(9),c(d);var g=i(d);o(g,`id`,`prerequisites`);var _=i(g),ae=i(n(_),2);ae.nodeValue=` present). The commands below use libvirt and
`,l(4),c(_);var v=i(_);m(v,{lang:`sh`,dangerous_raw_html:`sudo apt install -y virtinst libvirt-daemon-system qemu-system-x86 qemu-utils
sudo systemctl enable --now libvirtd
sudo virsh net-start default<span class="token_punctuation">;</span> sudo virsh net-autostart default   <span class="token_comment"># NAT network up</span>
sudo adduser <span class="token_string">"<span class="token_variable">$USER</span>"</span> libvirt   <span class="token_comment"># reach qemu:///system without a polkit password prompt</span>`});var y=i(v),oe=i(n(y),4);oe.nodeValue=`
commands below, and the differential harness, run without a password. Debian's
`,l(4),c(y);var se=i(y);o(se,`id`,`the-alpine-vm`);var ce=i(se,2);o(ce,`id`,`1-bring-up-the-vm`);var le=i(ce,2);m(le,{lang:`sh`,dangerous_raw_html:`base=https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64
iso=<span class="token_command_substitution"><span class="token_punctuation">$(</span>curl -s <span class="token_variable">$base</span>/ <span class="token_operator">|</span> grep -o <span class="token_string">'alpine-virt-[0-9.]*-x86_64.iso'</span> <span class="token_operator">|</span> sort -u <span class="token_operator">|</span> head -<span class="token_number">1</span><span class="token_punctuation">)</span></span>
sudo curl -fL -o /var/lib/libvirt/images/alpine-virt.iso <span class="token_string">"<span class="token_variable">$base</span>/<span class="token_variable">$iso</span>"</span>`});var ue=i(le,2);m(ue,{lang:`sh`,dangerous_raw_html:`sudo virt-install --name alpine-zap --memory <span class="token_number">1024</span> --vcpus <span class="token_number">2</span> \\
  --disk size=<span class="token_number">4</span><span class="token_punctuation">,</span>format=qcow2 \\
  --cdrom /var/lib/libvirt/images/alpine-virt.iso \\
  --osinfo generic --network network=default \\
  --graphics none --console pty<span class="token_punctuation">,</span>target_type=serial`});var b=i(ue,3),de=i(n(b),4);de.nodeValue=`. From now on it's
`,l(6),c(b);var x=i(b),fe=i(n(x),3);fe.nodeValue=` network leases it. The differential harness expects it at
`,l(6),c(x);var pe=i(x);m(pe,{lang:`sh`,dangerous_raw_html:`virsh -c qemu:///system net-update default add ip-dhcp-host \\
  <span class="token_string">"&lt;host mac='&lt;mac>' name='alpine-zap' ip='192.168.122.10'/>"</span> --live --config`});var S=i(pe);o(S,`id`,`2-make-it-zap-drivable`);var C=i(S),me=i(n(C),8);me.nodeValue=` installed and a NOPASSWD sudoer. On Alpine,
`,l(6),c(C);var w=i(C);m(w,{lang:`sh`,dangerous_raw_html:`<span class="token_comment"># in the VM, as root:</span>
setup-apkrepos -c -f          <span class="token_comment"># enable the community repo + fastest mirror</span>
apk update <span class="token_operator">&amp;&amp;</span> apk add sudo
adduser ops wheel
<span class="token_builtin">echo</span> <span class="token_string">'%wheel ALL=(ALL) NOPASSWD: ALL'</span> <span class="token_operator">></span> /etc/sudoers.d/wheel
chmod <span class="token_number">0440</span> /etc/sudoers.d/wheel`});var T=i(w,2);m(T,{lang:`sh`,dangerous_raw_html:`<span class="token_comment"># on the host:</span>
ssh-copy-id ops@<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span>
ssh ops@<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> <span class="token_boolean">true</span>          <span class="token_comment"># must return silently</span>`});var E=i(T);o(E,`id`,`3-run-zap-against-it`);var D=i(E),O=i(n(D),2);O.nodeValue=` in a directory of its own, beside a
`;var he=i(O,3);he.textContent=`{"name": "zap-alpine-probe", "type": "module"}`,l(7),c(D);var k=i(D);m(k,{lang:`ts`,dangerous_raw_html:`<span class="token_comment">// zap.ts</span>
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
<span class="token_punctuation">};</span>`});var A=i(k),ge=i(n(A),5);l(9),c(A);var j=i(A);m(j,{lang:`sh`,dangerous_raw_html:`env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap lock            <span class="token_comment"># pin the fgro build ZAP_FGRO names</span>
env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap detect          <span class="token_comment"># probe sanity</span>
env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap apply           <span class="token_comment"># dry-run: see the plan</span>
env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap apply --wetrun  <span class="token_comment"># converge</span>
env ALPINE_HOST=<span class="token_operator">&lt;</span>vm-ip<span class="token_operator">></span> ALPINE_USER=ops zap apply           <span class="token_comment"># idempotency re-check</span>`});var M=i(j,2),N=i(n(M)),P=i(n(N),4);P.nodeValue=`) ahead of
`;var _e=i(P,4);_e.nodeValue=` and
`,l(4),c(N);var F=i(N,2),ve=i(n(F),6);ve.nodeValue=`, the service's entry under
`,l(4),c(F),c(M);var I=i(M);o(I,`id`,`the-debian-vm`);var L=i(I,2);o(L,`id`,`1-fetch-and-verify-the-cloud-image`);var R=i(L);m(R,{lang:`sh`,dangerous_raw_html:`base=https://cloud.debian.org/images/cloud/trixie/latest
curl -fLO <span class="token_variable">$base</span>/debian-<span class="token_number">13</span>-genericcloud-amd64.qcow2
curl -fLO <span class="token_variable">$base</span>/SHA512SUMS
sha512sum --ignore-missing -c SHA512SUMS   <span class="token_comment"># must print "debian-13-genericcloud-amd64.qcow2: OK"</span>
qemu-img resize debian-<span class="token_number">13</span>-genericcloud-amd64.qcow2 8G   <span class="token_comment"># cloud-init grows / on first boot</span>`});var z=i(R);o(z,`id`,`2-write-the-cloud-init-seed`);var B=i(z,2);m(B,{lang:`yaml`,content:`#cloud-config
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
package_update: false`});var V=i(B,2);m(V,{lang:`yaml`,content:`instance-id: debian-zap
local-hostname: debian-zap`});var H=i(V,2);m(H,{lang:`yaml`,content:`version: 2
ethernets:
  primary:
    match:
      name: "en*"
    addresses: [192.168.122.11/24]
    routes:
      - to: default
        via: 192.168.122.1
    nameservers:
      addresses: [192.168.122.1]`});var U=i(H,2);m(U,{lang:`sh`,content:`xorriso -as mkisofs -output debian-zap-seed.iso -volid cidata -joliet -rock \\
  user-data meta-data network-config`});var W=i(U);o(W,`id`,`3-upload-both-into-the-default-pool`);var ye=i(W,2);m(ye,{lang:`sh`,dangerous_raw_html:`v=<span class="token_string">"virsh -c qemu:///system"</span>
<span class="token_variable">$v</span> vol-create-as default debian-zap.qcow2 8G --format qcow2
<span class="token_variable">$v</span> vol-upload --pool default debian-zap.qcow2 debian-<span class="token_number">13</span>-genericcloud-amd64.qcow2
<span class="token_variable">$v</span> vol-create-as default debian-zap-seed.iso <span class="token_command_substitution"><span class="token_punctuation">$(</span>stat -c %s debian-zap-seed.iso<span class="token_punctuation">)</span></span> --format raw
<span class="token_variable">$v</span> vol-upload --pool default debian-zap-seed.iso debian-zap-seed.iso`});var be=i(ye);o(be,`id`,`4-create-the-domain`);var xe=i(be);m(xe,{lang:`sh`,dangerous_raw_html:`virt-install --connect qemu:///system --name debian-zap --memory <span class="token_number">1024</span> --vcpus <span class="token_number">2</span> \\
  --disk vol=default/debian-zap.qcow2<span class="token_punctuation">,</span>bus=virtio \\
  --disk vol=default/debian-zap-seed.iso<span class="token_punctuation">,</span>device=cdrom \\
  --import --osinfo debian13 --network network=default \\
  --graphics none --video vga --console pty<span class="token_punctuation">,</span>target_type=serial --noautoconsole`});var G=i(xe,2),Se=n(G);Se.nodeValue=`First boot runs cloud-init. Then
`;var Ce=i(Se,4);Ce.nodeValue=` comes from
`,l(2),c(G);var we=i(G);m(we,{lang:`sh`,dangerous_raw_html:`virsh -c qemu:///system net-update default add ip-dhcp-host \\
  <span class="token_string">"&lt;host mac='&lt;mac>' name='debian-zap' ip='192.168.122.11'/>"</span> --live --config`});var Te=i(we,2);o(Te,`id`,`5-snapshot-both-vms`);var K=i(Te),Ee=n(K);Ee.nodeValue=`The differential harness starts every base build from a snapshot named
`,l(2),c(K);var De=i(K);m(De,{lang:`sh`,content:`virsh -c qemu:///system snapshot-create-as debian-zap pristine
virsh -c qemu:///system snapshot-create-as alpine-zap pristine`});var Oe=i(De);o(Oe,`id`,`gotchas`);var q=i(Oe),ke=i(n(q),5);ke.nodeValue=` can't read. Keep it in
`,l(2),c(q);var J=i(q),Ae=i(n(J));Ae.nodeValue=`
(`;var je=i(Ae,4);je.nodeValue=` group, so polkit falls back to admin auth. Run
`,l(2),c(J);var Y=i(J),Me=i(n(Y),11);Me.nodeValue=` and
`;var Ne=i(Me,2);Ne.nodeValue=` chains, for example
`,l(2),c(Y);var X=i(Y),Pe=i(n(X));Pe.nodeValue=` The interface is down. Run
`;var Fe=i(Pe,4);Fe.nodeValue=`. This is only relevant when testing before
`,l(2),c(X);var Z=i(X),Ie=i(n(Z),7);Ie.nodeValue=` goes
`,l(2),c(Z);var Q=i(Z),Le=i(n(Q),3);Le.nodeValue=`, keeping
`,l(2),c(Q);var $=i(Q),Re=i(n($));Re.nodeValue=` with
`;var ze=i(Re,2);ze.nodeValue=`. The guest resumed with the
clock it had when the snapshot was taken. Set it from the host with
`,l(2),c($);var Be=i($,3),Ve=n(Be),He=i(n(Ve),4);He.nodeValue=` archive relies on a target-side
`,l(2),c(Ve),l(11),c(Be),re((e,t,ee,n)=>{o(ne,`href`,e),o(f,`href`,t),o(h,`href`,ee),o(ge,`href`,n)},[()=>u(`docs/getting-started`),()=>u(`docs/contributing#the-hermetic-suites`),()=>u(`docs/differential`),()=>u(`docs/install#getting-fgro`)]),te(e,r)},$$slots:{default:!0}})},$$slots:{default:!0}}),r()}export{h as t};