//! `user` step builder — guarded `useradd` plus idempotent shell / SSH-key /
//! sudoers writes.

use crate::detected::Detection;
use crate::plan::{
    DirStep, PlanStep, PutAs, PutCommand, PutMode, PutProducer, PutSource, PutStep, PutText,
};
use crate::put::PutCheck;
use crate::scalar::{AccountName, Mode};
use crate::schema::{
    SshKeys, UserResource, UserSudo, authorized_keys_path, build_sudoers_content,
    render_authorized_keys, sudoers_path, user_home_dir, user_ssh_dir,
};
use crate::shell::single_quote;

/// Idempotent, self-contained steps for a `user`: `useradd` is guarded by an existence
/// check, `usermod` / `chmod` are idempotent, and the `authorized_keys` / sudoers
/// writes replace the file with the declared content.
///
/// Both writes are [`PutStep`]s — staged, then renamed into place with the mode already
/// set — holding the text they install, which is the text detection compares against
/// ([`render_authorized_keys`], [`build_sudoers_content`]):
///
/// - `~/.ssh` is the account's own directory, so its steps follow nothing the account
///   could plant: the directory's owner and mode are set by a [`DirStep`], which
///   refuses a symbolic link at `.ssh`, and `authorized_keys` is written as the account
///   (`sudo -u`), which can write only what the account already could. A `copy_from`
///   source is read on the target, as the source account.
/// - The sudoers file is checked by `visudo` before it is installed.
///
/// `detected` adds the one step that depends on what was found: when the account is
/// absent and `home_mode` or `ssh_keys` is declared, the creation gives the home
/// directory itself to the user and its primary group ([`home_owner_step`]), since
/// `useradd` leaves a directory already there as it was (root's: detection holds any
/// other owner). An existing account's home keeps its owner.
pub(super) fn user_steps(user: &UserResource, detected: Option<&Detection>) -> Vec<PlanStep> {
    let u = &user.username;
    let shell_arg = user
        .shell
        .as_ref()
        .map_or(String::new(), |s| format!(" -s {}", single_quote(s)));
    // The home is named (`-d`), not left to the distro default (`/etc/default/useradd`'s
    // `HOME`), so it is the `/home/<name>` every other step and the detector act on.
    let mut steps = vec![PlanStep::run(format!(
        "id -u -- {0} >/dev/null 2>&1 || sudo useradd -m -d {1}{shell_arg} -- {0}",
        single_quote(u),
        single_quote(&user_home_dir(u))
    ))];
    // An absent account's home is nothing, or a directory root owns: detection holds any
    // other. Either way the step leaves the directory the user's.
    let manages_home = user.home_mode.is_some() || user.ssh_keys.is_some();
    if manages_home && matches!(detected, Some(Detection::Absent)) {
        steps.push(home_owner_step(u));
    }
    if let Some(shell) = &user.shell {
        steps.push(PlanStep::run(format!(
            "sudo usermod -s {} -- {}",
            single_quote(shell),
            single_quote(u)
        )));
    }
    if !user.groups.is_empty() {
        // Supplementary-group membership is additive (`-aG`): the listed groups are added,
        // groups the config omits are left untouched. Idempotent — re-adding an existing
        // membership is a no-op.
        let group_list = user
            .groups
            .iter()
            .map(AccountName::as_str)
            .collect::<Vec<_>>()
            .join(",");
        steps.push(PlanStep::run(format!(
            "sudo usermod -aG {} -- {}",
            single_quote(&group_list),
            single_quote(u)
        )));
    }
    if let Some(mode) = &user.home_mode {
        steps.push(PlanStep::run(format!(
            "sudo chmod {mode} -- {}",
            single_quote(&user_home_dir(u))
        )));
    }
    if let Some(ssh_keys) = &user.ssh_keys {
        // The home is the account's own or root's, so `.ssh` is a name only it or root controls. `mkdir -p`
        // creates nothing through a link; the attrs script then refuses a link there
        // and sets the owner and mode on the directory it holds open.
        steps.push(PlanStep::Dir(DirStep {
            path: user_ssh_dir(u),
            mode: Mode::fixed("700"),
            owner: u.clone(),
            group: u.clone(),
        }));
        // The key file is written as the account itself: whatever it plants in its own
        // `.ssh`, the write can reach nothing the account couldn't already write.
        let source = match ssh_keys {
            // The source is read as the source account, so a link it plants at its own
            // key file can't make the step copy a file only root may read. Its home is
            // read first, in the step's own shell, for the producer to name.
            SshKeys::CopyFrom { copy_from } => PutSource::Command(PutCommand {
                mode: PutMode::Set(Mode::fixed("600")),
                producer: PutProducer::AuthorizedKeysOf {
                    account: copy_from.clone(),
                },
            }),
            SshKeys::Keys { keys } => PutSource::Text(PutText {
                mode: Mode::fixed("600"),
                content: render_authorized_keys(keys),
            }),
        };
        steps.push(PlanStep::Put(PutStep {
            path: authorized_keys_path(u),
            run_as: PutAs::User(u.clone()),
            check: PutCheck::None,
            source,
        }));
        // alpine `useradd` leaves the shadow password field `!`-locked, and alpine sshd
        // refuses pubkey login to a locked account; set `*` (no password, NOT locked) so
        // an `ssh_keys` user is reachable. the literal single-quoted `*` blocks glob
        // expansion; idempotent, and harmless on debian's lenient sshd
        steps.push(PlanStep::run(format!(
            "sudo usermod -p '*' -- {}",
            single_quote(u)
        )));
    }
    match user.sudo.as_ref().map(UserSudo::grant) {
        None => {}
        Some(None) => {
            // `Disabled` — remove any sudoers file.
            steps.push(PlanStep::run(format!(
                "sudo rm -f -- {}",
                single_quote(&sudoers_path(u))
            )));
        }
        Some(Some((mode, scope))) => {
            let content = build_sudoers_content(u, mode, scope);
            // Staged, checked by `visudo`, and only then renamed into place at `0440`: a
            // file that doesn't parse would lock `sudo` out, so it is never installed.
            steps.push(PlanStep::Put(PutStep {
                path: sudoers_path(u),
                run_as: PutAs::Root,
                check: PutCheck::Sudoers,
                source: PutSource::Text(PutText {
                    mode: Mode::fixed("440"),
                    content: format!("{}\n", content.trim_end_matches('\n')),
                }),
            }));
        }
    }
    steps
}

/// Give `/home/<name>` itself to the user and its primary group: `chown -h`, so a link
/// planted at the name since detection is changed rather than followed, and never
/// recursive. `<name>:`, a trailing colon and no group, names the user's login group in
/// GNU and `BusyBox` `chown` alike.
fn home_owner_step(username: &AccountName) -> PlanStep {
    PlanStep::run(format!(
        "sudo chown -h -- {} {}",
        single_quote(&format!("{}:", username.as_str())),
        single_quote(&user_home_dir(username))
    ))
}

#[cfg(test)]
mod tests {
    use super::user_steps;
    use crate::detected::{CurrentState, Detection, UserDrift};
    use crate::plan::{
        DirStep, PlanStep, PutAs, PutCommand, PutMode, PutProducer, PutSource, PutStep, PutText,
        StepExecution,
    };
    use crate::put::{FILE_PUT, FileAttrs, PutCheck, RunAs, dir_attrs_command, put_text_step};
    use crate::scalar::{AccountName, Mode};
    use crate::schema::UserResource;

    /// The shell text each step runs: a command's whole text, a text put's put command.
    fn runs(user: &UserResource) -> Vec<String> {
        user_steps(user, None)
            .iter()
            .filter_map(PlanStep::execution)
            .map(|execution| execution.text().to_owned())
            .collect()
    }

    fn user(json: serde_json::Value) -> UserResource {
        serde_json::from_value(json).expect("valid user json")
    }

    fn mode(mode: &str) -> Mode {
        Mode::new(mode).unwrap()
    }

    fn account(name: &str) -> AccountName {
        AccountName::new(name).unwrap()
    }

    /// What `printf '%s\n' <args>` prints: each argument and a newline.
    fn printf_lines(args: &[&str]) -> String {
        let mut printed = String::new();
        for arg in args {
            printed.push_str(arg);
            printed.push('\n');
        }
        printed
    }

    #[test]
    fn guarded_useradd_with_shell() {
        let runs = runs(&user(serde_json::json!({
            "username": "deploy", "shell": "/bin/bash"
        })));
        assert!(
            runs.contains(
                &"id -u -- 'deploy' >/dev/null 2>&1 || \
                  sudo useradd -m -d '/home/deploy' -s '/bin/bash' -- 'deploy'"
                    .to_owned()
            )
        );
    }

    #[test]
    fn supplementary_groups_are_added_with_usermod_ag() {
        let runs = runs(&user(serde_json::json!({
            "username": "deploy", "groups": ["docker", "www-data"]
        })));
        assert!(runs.contains(&"sudo usermod -aG 'docker,www-data' -- 'deploy'".to_owned()));
    }

    #[test]
    fn no_groups_emits_no_usermod_ag() {
        let runs = runs(&user(serde_json::json!({"username": "deploy"})));
        assert!(!runs.iter().any(|c| c.contains("usermod -aG")));
    }

    #[test]
    fn sudoers_is_put_at_0440_through_the_visudo_check() {
        let declared = user(serde_json::json!({
            "username": "deploy", "sudo": "nopasswd"
        }));
        let steps = user_steps(&declared, None);
        // The text is the line a `printf '%s\n' 'deploy ALL=(ALL) NOPASSWD: ALL'` prints.
        let step = PlanStep::Put(PutStep {
            path: "/etc/sudoers.d/deploy".to_owned(),
            run_as: PutAs::Root,
            check: PutCheck::Sudoers,
            source: PutSource::Text(PutText {
                mode: mode("440"),
                content: printf_lines(&["deploy ALL=(ALL) NOPASSWD: ALL"]),
            }),
        });
        assert_eq!(steps.last(), Some(&step));
        // It runs the put script as root with the check, the text on its stdin.
        assert_eq!(
            step.execution(),
            Some(StepExecution::Put {
                command: format!(
                    "sudo sh -c '{FILE_PUT}' sh '/etc/sudoers.d/deploy' '440' '' 'sudoers' ''"
                ),
                content: "deploy ALL=(ALL) NOPASSWD: ALL\n",
            })
        );
        // Nothing writes the file in place, and no command names it to change its mode.
        let runs = runs(&declared);
        assert!(!runs.iter().any(|c| c.contains("tee ")));
        assert!(!runs.iter().any(|c| c.contains("chmod 440")));
    }

    /// A restricted grant is one sudoers line. A command that would end the line
    /// early — one that holds a line break, at its end included — is no config: the
    /// parse refuses it, so the text is never built from one.
    #[test]
    fn restricted_sudoers_text_is_one_line() {
        let steps = user_steps(
            &user(serde_json::json!({
                "username": "deploy",
                "sudo": {"mode": "password", "commands": ["/bin/a", "/bin/b"]},
            })),
            None,
        );
        let Some(PlanStep::Put(PutStep {
            source: PutSource::Text(text),
            ..
        })) = steps.last()
        else {
            panic!("expected a text put, got {:?}", steps.last());
        };
        assert_eq!(
            text.content,
            printf_lines(&["deploy ALL=(ALL) /bin/a, /bin/b"])
        );
        let error = serde_json::from_value::<UserResource>(serde_json::json!({
            "username": "deploy",
            "sudo": {"mode": "password", "commands": ["/bin/a\n\n"]},
        }))
        .unwrap_err()
        .to_string();
        assert!(
            error.starts_with("`sudo.commands[0]` holds a control character"),
            "{error}"
        );
    }

    #[test]
    fn sudo_false_removes_the_drop_in() {
        let runs = runs(&user(serde_json::json!({
            "username": "limited", "sudo": false
        })));
        assert!(runs.contains(&"sudo rm -f -- '/etc/sudoers.d/limited'".to_owned()));
        assert!(!runs.iter().any(|c| c.contains(FILE_PUT)));
    }

    /// The put of `/home/deploy/.ssh/authorized_keys` as `deploy`, fed by `producer`.
    fn keys_put(producer: &str) -> String {
        put_text_step(
            producer,
            RunAs::User("deploy"),
            "/home/deploy/.ssh/authorized_keys",
            FileAttrs::mode("600"),
            PutCheck::None,
        )
    }

    #[test]
    fn ssh_keys_copy_from_reads_the_source_as_the_source_account() {
        // `copy_from` resolves the source user's home by parsing `/etc/passwd`,
        // byte-identical to the detector's shared `passwd_field` probe, and reads the
        // key file as that user.
        let declared = user(serde_json::json!({
            "username": "deploy", "ssh_keys": {"copy_from": "root"}
        }));
        assert!(
            user_steps(&declared, None).contains(&PlanStep::Put(PutStep {
                path: "/home/deploy/.ssh/authorized_keys".to_owned(),
                run_as: PutAs::User(account("deploy")),
                check: PutCheck::None,
                source: PutSource::Command(PutCommand {
                    mode: PutMode::Set(mode("600")),
                    producer: PutProducer::AuthorizedKeysOf {
                        account: account("root"),
                    },
                }),
            }))
        );
        assert!(runs(&declared).contains(&format!(
            "SRC_HOME=$(awk -F: -v u='root' '$1\"\"==u{{print $6}}' /etc/passwd) && \
             [ -n \"$SRC_HOME\" ] || {{ echo 'zap: no home directory for root' >&2; exit 1; }}; {}",
            keys_put("sudo -u 'root' cat -- \"$SRC_HOME/.ssh/authorized_keys\"")
        )));
    }

    /// The step that copies a source account's keys and the detector's read of them
    /// find the account's home by one read and read the file as one account: each is
    /// built from `copy_source_home` and `copy_source_keys`, and they differ only in
    /// what a missing home means and in how much of the file is read.
    #[test]
    fn the_copy_from_step_and_the_detectors_read_share_the_home_and_the_reader() {
        use crate::observe::user::copy_source_snippet;
        use crate::schema::{copy_source_home, copy_source_keys};

        let home = copy_source_home("ops");
        let declared = user(serde_json::json!({
            "username": "deploy", "ssh_keys": {"copy_from": "ops"}
        }));
        let step = runs(&declared)
            .into_iter()
            .find(|text| text.contains("authorized_keys"))
            .expect("the key file's step");
        assert_eq!(
            step,
            format!(
                "{home} || {{ echo 'zap: no home directory for ops' >&2; exit 1; }}; {}",
                keys_put(&copy_source_keys("ops", "cat"))
            )
        );
        assert_eq!(
            copy_source_snippet("ops"),
            format!(
                "{home} || exit 3; exec {}",
                copy_source_keys("ops", "head -c 1048577")
            )
        );
    }

    #[test]
    fn ssh_keys_are_put_as_the_account_into_a_directory_it_is_given() {
        let declared = user(serde_json::json!({
            "username": "deploy", "ssh_keys": {"keys": ["ssh-ed25519 AAA o'brien", "ssh-rsa B"]}
        }));
        let steps = user_steps(&declared, None);
        let runs = runs(&declared);
        // `.ssh` is made, then set to `700 deploy:deploy` through a descriptor.
        assert!(steps.contains(&PlanStep::Dir(DirStep {
            path: "/home/deploy/.ssh".to_owned(),
            mode: mode("700"),
            owner: account("deploy"),
            group: account("deploy"),
        })));
        assert!(runs.contains(&format!(
            "sudo mkdir -p -- '/home/deploy/.ssh' && {}",
            dir_attrs_command(
                RunAs::Root,
                "/home/deploy/.ssh",
                FileAttrs {
                    mode: Some("700"),
                    owner: Some("deploy"),
                    group: Some("deploy"),
                    ..FileAttrs::NONE
                },
            )
        )));
        // The text is what `printf '%s\n' 'ssh-ed25519 AAA o'\''brien' 'ssh-rsa B'`
        // prints — each key a line, as declared — and the file is written by `deploy`.
        let put = PlanStep::Put(PutStep {
            path: "/home/deploy/.ssh/authorized_keys".to_owned(),
            run_as: PutAs::User(account("deploy")),
            check: PutCheck::None,
            source: PutSource::Text(PutText {
                mode: mode("600"),
                content: printf_lines(&["ssh-ed25519 AAA o'brien", "ssh-rsa B"]),
            }),
        });
        assert!(steps.contains(&put), "{steps:?}");
        assert_eq!(
            put.execution(),
            Some(StepExecution::Put {
                command: format!(
                    "sudo -u 'deploy' sh -c '{FILE_PUT}' sh \
                     '/home/deploy/.ssh/authorized_keys' '600' '' '' ''"
                ),
                content: "ssh-ed25519 AAA o'brien\nssh-rsa B\n",
            })
        );
        // No command writes the file in place, or names it (or a tree) to change a mode
        // or an owner — each would follow a link the account planted.
        for gone in ["tee ", "chown -R", "chmod 600"] {
            assert!(!runs.iter().any(|c| c.contains(gone)), "{gone}: {runs:?}");
        }
    }

    #[test]
    fn ssh_keys_user_is_shadow_unlocked() {
        // An `ssh_keys` user is shadow-unlocked (`usermod -p '*'`) so Alpine's sshd
        // accepts pubkey login; a user without `ssh_keys` emits no unlock step.
        let with_keys = runs(&user(serde_json::json!({
            "username": "deploy", "ssh_keys": {"keys": ["ssh-ed25519 AAAA deploy"]}
        })));
        assert!(with_keys.contains(&"sudo usermod -p '*' -- 'deploy'".to_owned()));

        let without_keys = runs(&user(serde_json::json!({
            "username": "deploy", "shell": "/bin/bash"
        })));
        assert!(!without_keys.iter().any(|c| c.contains("usermod -p")));
    }

    /// The home's owner change: the directory itself (`-h`, never `-R`), to the user and
    /// its login group (`deploy:`), right after the account is created — only for an
    /// absent account with an attribute under its home.
    #[test]
    fn a_created_users_home_is_given_to_it_after_useradd() {
        let chown = "sudo chown -h -- 'deploy:' '/home/deploy'".to_owned();
        let useradd =
            "id -u -- 'deploy' >/dev/null 2>&1 || sudo useradd -m -d '/home/deploy' -- 'deploy'";
        let managed = user(serde_json::json!({"username": "deploy", "home_mode": "750"}));
        let texts = |user: &UserResource, detected: &Detection| -> Vec<String> {
            user_steps(user, Some(detected))
                .iter()
                .filter_map(PlanStep::execution)
                .map(|execution| execution.text().to_owned())
                .collect()
        };
        assert_eq!(
            texts(&managed, &Detection::Absent),
            [
                useradd.to_owned(),
                chown.clone(),
                "sudo chmod 750 -- '/home/deploy'".to_owned()
            ]
        );

        // An existing account's home keeps its owner, root's included; a user with
        // nothing under its home changes none.
        let mode_only = Detection::Drifted {
            current: CurrentState::User {
                drift: UserDrift {
                    home_mode: Some("755".to_owned()),
                    ..UserDrift::default()
                },
            },
        };
        assert!(!texts(&managed, &mode_only).contains(&chown));
        let shell_only = user(serde_json::json!({"username": "deploy", "shell": "/bin/sh"}));
        assert!(
            !texts(&shell_only, &Detection::Absent)
                .iter()
                .any(|t| t.contains("chown"))
        );
        assert!(
            !runs(&managed).iter().any(|t| t.contains("chown")),
            "no detection"
        );
    }
}
