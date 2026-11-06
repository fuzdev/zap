//! `installer` step builder — fetch an installer script and pipe it into a shell.

use crate::plan::{InstallerStep, PlanStep};
use crate::schema::InstallerResource;

/// The one step of an `installer`: an [`InstallerStep`] of its `url` and `shell`, each
/// as declared. `check` is detection's — it is no part of the step.
pub(super) fn installer_steps(installer: &InstallerResource) -> Vec<PlanStep> {
    vec![PlanStep::Installer(InstallerStep {
        url: installer.url.as_inert().to_owned(),
        shell: installer.shell.as_inert().to_owned(),
    })]
}

#[cfg(test)]
mod tests {
    use super::installer_steps;
    use crate::plan::{InstallerStep, PlanStep, StepExecution};
    use crate::schema::InstallerResource;
    use crate::var_ref::marker;

    fn installer(json: serde_json::Value) -> InstallerResource {
        serde_json::from_value(json).expect("valid installer json")
    }

    fn step(url: &str, shell: &str) -> PlanStep {
        PlanStep::Installer(InstallerStep {
            url: url.to_owned(),
            shell: shell.to_owned(),
        })
    }

    #[test]
    fn pipes_the_fetched_script_into_the_given_shell() {
        let steps = installer_steps(&installer(serde_json::json!({
            "url": "https://deno.land/install.sh",
            "check": "~/.deno/bin/deno",
            "shell": "bash"
        })));
        assert_eq!(steps, vec![step("https://deno.land/install.sh", "bash")]);
        assert_eq!(
            steps[0].execution(),
            Some(StepExecution::Command(
                "zap_s=$(curl --proto '=https' --proto-redir '=https' -fsSL -- \
                 'https://deno.land/install.sh') || exit; \
                 [ -n \"$zap_s\" ] || { echo 'zap: the installer script is empty' >&2; exit 1; }; \
                 printf '%s\\n' \"$zap_s\" | bash"
                    .to_owned()
            ))
        );
    }

    #[test]
    fn shell_defaults_to_sh() {
        // The schema default (`sh`) lands as the pipe target when `shell` is omitted.
        let steps = installer_steps(&installer(serde_json::json!({
            "url": "https://example.com/i.sh",
            "check": "/usr/local/bin/tool"
        })));
        assert_eq!(steps, vec![step("https://example.com/i.sh", "sh")]);
        assert_eq!(
            steps[0].execution().unwrap().text(),
            "zap_s=$(curl --proto '=https' --proto-redir '=https' -fsSL -- \
             'https://example.com/i.sh') || exit; \
             [ -n \"$zap_s\" ] || { echo 'zap: the installer script is empty' >&2; exit 1; }; \
             printf '%s\\n' \"$zap_s\" | sh"
        );
    }

    #[test]
    fn the_url_is_one_quoted_word_and_the_shell_is_run_as_written() {
        let steps = installer_steps(&installer(serde_json::json!({
            "url": "https://example.com/it's.sh",
            "check": "/usr/local/bin/tool",
            "shell": "sh -s -- --yes"
        })));
        let text = steps[0].execution().unwrap().text().to_owned();
        assert!(
            text.contains(r" -- 'https://example.com/it'\''s.sh') || exit; "),
            "{text}"
        );
        assert!(text.ends_with(" | sh -s -- --yes"), "{text}");
    }

    #[test]
    fn a_reference_in_the_url_or_the_shell_stays_in_the_step() {
        // Each rides the step as declared, and is resolved when the step runs.
        let steps = installer_steps(&installer(serde_json::json!({
            "url": {"$text": ["https://", {"$env": "MIRROR"}, "/i.sh"]},
            "check": "/usr/local/bin/tool",
            "shell": {"$text": ["sh -s -- ", {"$env": "CHANNEL"}]},
        })));
        let url = format!("https://{}/i.sh", marker("MIRROR"));
        let shell = format!("sh -s -- {}", marker("CHANNEL"));
        assert_eq!(steps, vec![step(&url, &shell)]);
        let mut texts = Vec::new();
        steps[0].for_each_text(|text| texts.push(text.to_owned()));
        assert_eq!(texts, [url, shell]);
    }

    #[test]
    fn check_is_a_detection_input_not_a_step() {
        // `check` is the existence probe (detection); only `url` + `shell` form the
        // step, so the check path never appears in it.
        let steps = installer_steps(&installer(serde_json::json!({
            "url": "https://example.com/i.sh",
            "check": "/opt/tool/bin/tool",
            "shell": "sh"
        })));
        assert_eq!(steps.len(), 1);
        assert!(!steps[0].execution().unwrap().text().contains("/opt/tool"));
        assert!(
            !serde_json::to_string(&steps[0])
                .unwrap()
                .contains("/opt/tool")
        );
    }
}
