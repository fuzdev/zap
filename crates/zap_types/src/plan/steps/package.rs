//! `package` step builder — install via the target's package manager.

use crate::package_managers;
use crate::plan::PlanStep;
use crate::schema::{PackageResource, Target};

/// Install command for a `package`, or a preview `Note` when the manager is
/// unconfigured / unsupported, or the package has no name for the manager.
pub(super) fn package_steps(package: &PackageResource, target: &Target) -> Vec<PlanStep> {
    let Some(pm) = target.package_manager else {
        return vec![PlanStep::note("package manager not configured")];
    };
    let Some(name) = package.from.get(&pm) else {
        return vec![PlanStep::note(format!(
            "package not defined for {}",
            pm.as_str()
        ))];
    };
    package_managers::install(pm, name).map_or_else(
        || {
            vec![PlanStep::note(format!(
                "unsupported package manager: {}",
                pm.as_str()
            ))]
        },
        |cmd| vec![PlanStep::run(format!("sudo {cmd}"))],
    )
}

#[cfg(test)]
mod tests {
    use super::package_steps;
    use crate::package_managers;
    use crate::plan::PlanStep;
    use crate::schema::{PackageManager, PackageResource, Target};

    /// A `package` whose `from` map names `name` under manager key `pm` (a dynamic key,
    /// so the JSON object is built rather than written as a literal).
    fn package(pm: &str, name: &str) -> PackageResource {
        let from = serde_json::Value::Object(
            std::iter::once((pm.to_owned(), serde_json::Value::String(name.to_owned()))).collect(),
        );
        serde_json::from_value(serde_json::json!({"from": from})).expect("valid package json")
    }

    /// A local target with the given `package_manager` (or none).
    fn target(pm: Option<&str>) -> Target {
        let mut obj = serde_json::Map::new();
        obj.insert("local".to_owned(), serde_json::Value::Bool(true));
        if let Some(pm) = pm {
            obj.insert(
                "package_manager".to_owned(),
                serde_json::Value::String(pm.to_owned()),
            );
        }
        serde_json::from_value(serde_json::Value::Object(obj)).expect("valid target")
    }

    #[test]
    fn apt_install_is_prefixed_with_sudo() {
        let steps = package_steps(&package("apt", "nginx"), &target(Some("apt")));
        assert_eq!(
            steps,
            vec![PlanStep::run(
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nginx"
            )]
        );
    }

    #[test]
    fn no_package_manager_is_a_preview_note() {
        let steps = package_steps(&package("apt", "nginx"), &target(None));
        assert_eq!(
            steps,
            vec![PlanStep::note("package manager not configured")]
        );
    }

    #[test]
    fn package_not_defined_for_the_target_manager_is_a_note() {
        // The target runs apt, but the resource only names an apk package → a Note that
        // names the target's manager, never a malformed install command.
        let steps = package_steps(&package("apk", "nginx"), &target(Some("apt")));
        assert_eq!(steps, vec![PlanStep::note("package not defined for apt")]);
    }

    #[test]
    fn step_matches_the_package_managers_install_template_for_every_manager() {
        // Dispatch parity: the single-package step is exactly `sudo <install template>`,
        // pinning the builder to the shared `package_managers` seam the detector's `query`
        // counterpart also lives beside. Iterating the whole enum means a
        // backend is covered the moment its `install` arm returns `Some` — its case
        // flips from the Note to the real command with no test rewrite.
        for pm in [
            PackageManager::Apt,
            PackageManager::Apk,
            PackageManager::Pacman,
            PackageManager::Brew,
        ] {
            let steps = package_steps(&package(pm.as_str(), "curl"), &target(Some(pm.as_str())));
            // Built with the same `map_or_else` shape as the production builder, so the
            // assertion is "the step is exactly what the shared `install` template yields".
            let expected = package_managers::install(pm, "curl").map_or_else(
                || PlanStep::note(format!("unsupported package manager: {}", pm.as_str())),
                |cmd| PlanStep::run(format!("sudo {cmd}")),
            );
            assert_eq!(steps, vec![expected], "manager {}", pm.as_str());
        }
    }
}
