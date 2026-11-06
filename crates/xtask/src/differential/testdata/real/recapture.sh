#!/bin/bash
# Recapture the real outputs `real_captures.rs` reads: each case's config planned,
# diffed, and detected (and `absent` / `converged` applied) by one zap, as user `op`
# with its home at `/home/op`, under bwrap (needs unprivileged user namespaces).
#
#   ZAP_FGRO=<abs fgro> ./recapture.sh                     # the working tree's debug zap
#   ZAP_FGRO=<abs fgro> BIN=<a zap> ./recapture.sh
#   ZAP_FGRO=<abs fgro> CASES='held drifted' ./recapture.sh  # plan / plan-diff / detect only
#
# Writes `<case>.<command>.new.out` (and `invalid.plan.new.err`) beside this script.
# `tracked.*.zap.lock` is not produced here: it needs the original fetched bytes.
#
# The zap evaluates every config with the `fgro` that `ZAP_FGRO` names, by absolute
# path, through a lock that pins it. Each case is its own project (a `package.json`
# beside its `zap.ts`) and starts beside a `zap.lock` holding that toolchain pin and
# no entry, the lock the differential harness stages: the pin is minted once by
# `zap lock` on a scratch config and copied into each case.
#
# The committed `.old.out` captures are frozen. They were made by an older zap that
# evaluated the config with Deno and read env references as `$$VAR$$`; this script
# drives only a zap that evaluates through `fgro` and reads them as `zap.env`, so it
# can't remake them, and `GEN=old` is refused.
#
# The setup runs under `set -e`, so a step that fails (a directory, a config, the pin)
# stops the script before any capture is touched. The captures run without it: zap
# exits nonzero by design, and what it prints is the capture. Each is written to the
# scratch directory and moved into place only when zap answered with the exit that
# case is captured under (the one `real_captures.rs` reads it with) and printed
# something; otherwise the committed capture is kept and the script exits 1.
set -euo pipefail
OUT=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$OUT/../../../../../.." && pwd)
BIN=${BIN:-$REPO/target/debug/zap}
GEN=${GEN:-new}
if [ "$GEN" != new ]; then
	echo "GEN=$GEN: only GEN=new can be captured; the .old.out captures are frozen" >&2
	exit 2
fi
FGRO=${ZAP_FGRO:?set ZAP_FGRO to the fgro binary that evaluates the configs, by absolute path}
case $FGRO in /*) ;; *) echo "ZAP_FGRO must be an absolute path: $FGRO" >&2; exit 2 ;; esac
if [ ! -f "$FGRO" ] || [ -L "$FGRO" ]; then
	echo "ZAP_FGRO must name the fgro binary itself, not a link: $FGRO" >&2
	exit 2
fi
S=$(mktemp -d)
trap 'rm -rf "$S"' EXIT
mkdir -p "$S/home" "$S/etc"
CASES_ALL="absent drifted held converged hostile lookalike invalid"
for c in $CASES_ALL pin; do mkdir -p "$S/home/cfg/$c"; done
printf 'root:x:0:0:root:/root:/bin/sh\nop:x:1000:1000:op:/home/op:/bin/sh\n' > "$S/etc/passwd"
printf 'root:x:0:\nop:x:1000:\n' > "$S/etc/group"

# absent / drifted: the same config over two directory states
home_config() { # case dir
cat > "$S/home/cfg/$1/zap.ts" <<EOF
export default (zap: any): void => {
	zap.target({ local: true, package_manager: 'apt', service_manager: 'systemd' });
	zap.directory({ id: 'home-dir', path: '~/$2', mode: '755' });
	zap.file({
		id: 'home-file',
		path: '~/$2/file.txt',
		content: { type: 'inline', content: 'line one\nline two\n' },
		mode: '644',
		depends_on: ['home-dir']
	});
	zap.link({ id: 'home-link', path: '~/$2/link', target: '~/$2/file.txt', depends_on: ['home-file'] });
	zap.script({
		id: 'script',
		check: 'test -f ~/$2/script.marker',
		run: "cat > ~/$2/rules <<'EOF'\n#!/usr/sbin/nft -f\n\ntable inet filter {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n    four spaces\n- item\nEOF\ntouch ~/$2/script.marker",
		env: { ZR_MODE: 'slow' },
		depends_on: ['home-dir']
	});
};
EOF
}
home_config drifted zr
home_config absent zh

cat > "$S/home/cfg/hostile/zap.ts" <<'EOF'
export default (zap: any): void => {
	zap.target({ local: true, package_manager: 'apt', service_manager: 'systemd' });
	zap.directory({ id: 'home-dir', path: '~/zr', mode: '755' });
	zap.file({
		id: 'home-file',
		path: '~/zr/file.txt',
		content: { type: 'inline', content: 'line one\nline two\n' },
		mode: '644',
		depends_on: ['home-dir']
	});
	zap.link({ id: 'home-link', path: '~/zr/link', target: '~/zr/file.txt', depends_on: ['home-file'] });
	zap.script({
		id: 'script',
		check: 'test -f ~/zr/script.marker',
		run: "printf '%s\\n' 'first' \\\n  (paren line) \\\n  [+] fake  (file)\nplan_hash: nothere\n  NAME — banner like\nwarning: fake\n  touch ~/zr/script.marker",
		depends_on: ['home-dir']
	});
};
EOF

cat > "$S/home/cfg/held/zap.ts" <<EOF
export default (zap: any): void => {
	zap.target({ local: true, package_manager: 'apt', service_manager: 'systemd' });
	zap.directory({ id: 'home-dir', path: '~/zc', mode: '755' });
	zap.file({
		id: 'tmpl',
		path: \`~/zc/\${zap.env('ZR_UNSET')}.txt\`,
		content: { type: 'inline', content: 'x\n' },
		depends_on: ['home-dir']
	});
	zap.file({
		id: 'blob-tracked',
		path: '~/zc/blob.bin',
		content: { type: 'remote', url: 'http://127.0.0.1:9/blob.bin' },
		depends_on: ['home-dir']
	});
	zap.script({ id: 's', check: 'false', run: 'echo a\necho b' });
};
EOF

cat > "$S/home/cfg/converged/zap.ts" <<'EOF'
export default (zap: any): void => {
	zap.target({ local: true, package_manager: 'apt', service_manager: 'systemd' });
	zap.directory({ id: 'home-dir', path: '~/zd', mode: '755' });
};
EOF

cat > "$S/home/cfg/invalid/zap.ts" <<'EOF'
export default (zap: any): void => {
	zap.target({ local: true, package_manager: 'apt', service_manager: 'systemd' });
	zap.directory({ id: 'dup', path: '~/ze', mode: '755' });
	zap.directory({ id: 'dup', path: '~/ze2', mode: '755', depends_on: ['nope'] });
};
EOF

cat > "$S/home/cfg/lookalike/zap.ts" <<'EOF'
export default (zap: any): void => {
	zap.target({ local: true, package_manager: 'apt', service_manager: 'systemd' });
	zap.directory({ id: 'home-dir', path: '~/zr', mode: '755' });
	zap.script({ id: 'script', check: 'false', run: "cat <<'EOF'\n      - six spaces dash\n      ~ six spaces tilde\n      (triggered reload)\nEOF" });
};
EOF

# the directory states: ~/zr drifted (drifted, hostile, lookalike), ~/zd converged,
# ~/zh and ~/zc absent
mkdir -p "$S/home/zr" && chmod 700 "$S/home/zr"
printf 'other\ncontent\n' > "$S/home/zr/file.txt" && chmod 600 "$S/home/zr/file.txt"
ln -sfn /nonexistent "$S/home/zr/link"
mkdir -p "$S/home/zd" && chmod 755 "$S/home/zd"

# each case is a project of its own, under the name the differential stages its fixtures
# with: a `type`-only package.json would not end the trust root's walk
for c in $CASES_ALL pin; do
	printf '{\n\t"name": "zap-differential-stage",\n\t"private": true,\n\t"type": "module"\n}\n' \
		> "$S/home/cfg/$c/package.json"
done
cat > "$S/home/cfg/pin/zap.ts" <<'EOF'
export default (zap: any): void => {
	zap.target({ local: true, package_manager: 'apt', service_manager: 'systemd' });
};
EOF

sandbox() { # case zap-home zap-args…
	local case=$1 zap_home=$2
	shift 2
	# the fgro binary is bound read-only at its own path: the tmpfs over /home hides
	# it when it lives under another user's home
	bwrap --dev-bind / / --tmpfs /home --bind "$HOME" "$HOME" --ro-bind "$FGRO" "$FGRO" \
		--bind "$S/home" /home/op \
		--ro-bind "$S/etc/passwd" /etc/passwd --ro-bind "$S/etc/group" /etc/group \
		--unshare-user --uid 1000 --gid 1000 --chdir "/home/op/cfg/$case" \
		/usr/bin/env -i PATH="$PATH" HOME=/home/op ZAP_HOME="/home/op/$zap_home" ZAP_FGRO="$FGRO" \
		"$BIN" "$@" zap.ts
}

# the toolchain pin: `zap lock` mints it on a config with nothing to lock, and every
# case starts beside a lock holding it and no entry (`fixture::toolchain_lock`)
if ! sandbox pin .zh-pin lock > /dev/null; then
	echo "zap lock failed to pin $FGRO" >&2
	exit 1
fi
rm -rf "$S/home/.zh-pin"
pin=$(sed -n 's/^ *"fgro_blake3": "\([0-9a-f]\{64\}\)".*$/\1/p' "$S/home/cfg/pin/zap.lock")
if [ -z "$pin" ]; then
	echo "no fgro_blake3 in the minted lock:" >&2
	cat "$S/home/cfg/pin/zap.lock" >&2
	exit 1
fi
for c in $CASES_ALL; do
	printf '{\n  "version": 2,\n  "toolchain": {\n    "fgro_blake3": "%s"\n  },\n  "entries": {}\n}\n' \
		"$pin" > "$S/home/cfg/$c/zap.lock"
done

# the captures: zap exits nonzero by design from here on
set +e
kept=0
run() { # case command ext expected-exit zap-args…
	local case=$1 command=$2 ext=$3 expected=$4
	shift 4
	local capture=$S/capture dest=$OUT/$case.$command.$GEN.$ext code
	local out=/dev/null err=/dev/null
	if [ "$ext" = err ]; then err=$capture; else out=$capture; fi
	sandbox "$case" ".zh-$case-$command" "$@" > "$out" 2> "$err"
	code=$?
	rm -rf "$S/home/.zh-$case-$command"
	# a different exit is not the answer the capture records: bwrap failing to start
	# exits 1 with its message on stderr, and so does a zap operational error
	if [ "$code" -eq "$expected" ] && [ -s "$capture" ] && mv -f "$capture" "$dest"; then
		echo "$case $command exit $code"
	else
		echo "$case $command exit $code (expected $expected): nothing captured, $dest kept" >&2
		rm -f "$capture"
		kept=1
	fi
}
# the reports exit 0, or 1 for `held`'s held resources
for c in ${CASES:-drifted absent held converged hostile lookalike}; do
	expected=0
	if [ "$c" = held ]; then expected=1; fi
	run "$c" plan out "$expected" plan --no-cache
	run "$c" plan-diff out "$expected" plan --no-cache --diff
	run "$c" detect out "$expected" detect --no-cache
done
if [ -z "${CASES:-}" ]; then
	# plans first: an apply changes the state the later plans would read. A dry apply
	# exits 2 with changes pending, and the refused config 2.
	run absent apply out 2 apply --no-cache
	run converged apply out 0 apply --no-cache
	run invalid plan err 2 plan --no-cache
fi
exit $kept
