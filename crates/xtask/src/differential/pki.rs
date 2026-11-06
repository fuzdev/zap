//! The harness's test PKI: a certificate authority the guests are told to trust, and
//! the server certificate the content server presents under it.
//!
//! zap has a target fetch over `https` alone, and fetches over `https` itself from any
//! host but loopback, so what the harness serves a guest is served over TLS. The key
//! material is made once per machine with the system `openssl`, kept owner-only under
//! the operator's cache directory, and reused: the authority's certificate goes into
//! the fixtures (which install it in each guest's trust store), so it is part of a base
//! snapshot's identity and must not move between runs. Nothing here is committed, and
//! the authority is private to the machine that made it.
//!
//! Two certificates, because one won't do: a self-signed certificate is an authority
//! (`CA:TRUE`), which `curl` accepts from a server and zap's own client (rustls) does
//! not. So the authority signs a leaf (`CA:FALSE`) naming every address the server is
//! reached at.
//!
//! A guest trusts the authority for every fetch it makes, so the authority vouches for
//! nothing but the harness: its certificate carries critical name constraints
//! permitting exactly the names the leaf is issued for ([`ca_permits`]). A certificate
//! its key signs for any other name is refused by a client that trusts it.

use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::process;
use super::vm;

const CA_CERT: &str = "ca.crt";
const CA_KEY: &str = "ca.key";
/// The names the authority is constrained to ([`ca_permits`]), written last: its
/// presence says the authority is whole, and its content says whether it is held to
/// what is asked.
const CA_PERMITS: &str = "ca.permits";
const SERVER_CERT: &str = "server.crt";
const SERVER_KEY: &str = "server.key";
/// The names the server certificate was issued for, written last: its presence says
/// the leaf is whole, and its content says whether it still covers what is asked.
const SERVER_NAMES: &str = "server.names";

/// How long both certificates are valid, in days.
const VALID_DAYS: &str = "3650";

const OPENSSL_TIMEOUT: Duration = Duration::from_secs(60);

/// The authority's `openssl req` config, less its name constraints: a CA that signs
/// leaves and nothing below them.
const CA_CONFIG: &str = "[req]\n\
    distinguished_name = dn\n\
    prompt = no\n\
    x509_extensions = ext\n\
    [dn]\n\
    CN = zap differential test CA\n\
    [ext]\n\
    basicConstraints = critical,CA:TRUE,pathlen:0\n\
    keyUsage = critical,keyCertSign,cRLSign\n\
    subjectKeyIdentifier = hash\n";

/// The authority's `openssl req` config: [`CA_CONFIG`], and the critical name
/// constraints `permits` ([`ca_permits`]).
fn ca_config(permits: &str) -> String {
    format!("{CA_CONFIG}nameConstraints = critical,{permits}\n")
}

/// What an authority that signs a leaf for `names` is permitted to vouch for, as the
/// value of an `openssl` `nameConstraints`: each address alone, and each DNS name (with
/// the names under it).
///
/// A certificate's constraints bind only the kinds of name they mention: with no DNS
/// subtree every DNS name is open, and with no address every address is. So `names`
/// must hold at least one of each, and may hold nothing else.
///
/// # Errors
/// An entry that is neither `IP:<address>` nor `DNS:<name>`, or a list with no address
/// or no DNS name.
fn ca_permits(names: &[String]) -> Result<String, String> {
    let (mut addresses, mut dns) = (0, 0);
    let mut permits = Vec::with_capacity(names.len());
    for name in names {
        if let Some(address) = name.strip_prefix("IP:") {
            let mask = match address.parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => "255.255.255.255",
                Ok(IpAddr::V6(_)) => "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                Err(error) => return Err(format!("the test CA can't be held to {name}: {error}")),
            };
            addresses += 1;
            permits.push(format!("permitted;IP:{address}/{mask}"));
        } else if let Some(host) = name.strip_prefix("DNS:").filter(|host| is_dns_name(host)) {
            dns += 1;
            permits.push(format!("permitted;DNS:{host}"));
        } else {
            return Err(format!(
                "the test CA can't be held to {name}: a name is `IP:<address>` or `DNS:<name>`"
            ));
        }
    }
    if addresses == 0 || dns == 0 {
        return Err(format!(
            "the test CA is held to the names it serves, kind by kind: {} holds no {}, which \
             would leave every one open",
            names.join(","),
            if dns == 0 { "DNS name" } else { "address" }
        ));
    }
    Ok(permits.join(","))
}

/// Whether `host` is a DNS name an `openssl` config value can carry as it is: labels of
/// letters, digits and `-`, joined by single dots.
fn is_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// The leaf's `openssl` config for `names` (a `subjectAltName` value): a server
/// certificate, not an authority.
fn leaf_config(names: &str) -> String {
    format!(
        "[req]\n\
         distinguished_name = dn\n\
         prompt = no\n\
         [dn]\n\
         CN = zap differential content server\n\
         [ext]\n\
         basicConstraints = critical,CA:FALSE\n\
         keyUsage = critical,digitalSignature\n\
         extendedKeyUsage = serverAuth\n\
         subjectAltName = {names}\n\
         authorityKeyIdentifier = keyid\n"
    )
}

/// The names the content server's certificate must cover, as `subjectAltName` entries:
/// the libvirt gateway address a guest reaches it at, and this machine's own names.
pub fn server_names() -> Vec<String> {
    vec![
        format!("IP:{}", vm::LIBVIRT_GATEWAY),
        "IP:127.0.0.1".to_owned(),
        "DNS:localhost".to_owned(),
    ]
}

/// The test PKI in its directory, whole.
#[derive(Debug)]
pub struct Pki {
    dir: PathBuf,
    ca_pem: String,
    /// Set when a kept authority was replaced by this run ([`Pki::replaced`]).
    replaced: Option<String>,
}

impl Pki {
    /// Where the PKI is kept: `~/.cache/zap-differential/pki`.
    ///
    /// # Errors
    /// `HOME` is unset, empty, or not an absolute path.
    pub fn default_dir() -> Result<PathBuf, String> {
        Ok(super::cache_dir()?.join("pki"))
    }

    /// The PKI under `dir`, made with `openssl` where it is missing: an authority
    /// constrained to `names` when there is none, and a server certificate under it
    /// when there is none for exactly `names`. What is already there is reused
    /// untouched, and `openssl` is not run.
    ///
    /// A kept authority that isn't recorded as constrained to exactly `names` — one
    /// made with no constraints, or for other names — is no authority for this run: it
    /// is replaced, and the leaf with it ([`Pki::replaced`] says so). Its fingerprint
    /// moves, so every base that trusts the old one is rebuilt.
    ///
    /// # Errors
    /// `names` is not a list an authority can be constrained to ([`ca_permits`]), the
    /// directory can't be made private, `openssl` is missing or fails, or what is kept
    /// there can't be read as a certificate.
    pub fn ensure(dir: &Path, openssl: &Path, names: &[String]) -> Result<Self, String> {
        let permits = ca_permits(names)?;
        make_private_dir(dir)?;
        sweep_work_dirs(dir);
        let names = names.join(",");
        let has = |file: &str| dir.join(file).is_file();
        let kept_ca = has(CA_CERT) && has(CA_KEY);
        let has_ca = kept_ca
            && std::fs::read_to_string(dir.join(CA_PERMITS)).is_ok_and(|kept| kept == permits);
        let replaced = (kept_ca && !has_ca).then(|| {
            format!(
                "the test CA kept in {} was not constrained to {names}: a new one is made, \
                 and every base is rebuilt",
                dir.display()
            )
        });
        let has_leaf = has_ca
            && has(SERVER_CERT)
            && has(SERVER_KEY)
            && std::fs::read_to_string(dir.join(SERVER_NAMES)).is_ok_and(|kept| kept == names);
        if !has_leaf {
            let work = dir.join(format!("{WORK_PREFIX}{}", std::process::id()));
            make_private_dir(&work)?;
            let issued = Issuer {
                dir,
                work: &work,
                openssl,
            }
            .issue((!has_ca).then_some(permits.as_str()), &names);
            let _ = std::fs::remove_dir_all(&work);
            issued?;
        }
        let ca = dir.join(CA_CERT);
        let ca_pem = std::fs::read_to_string(&ca)
            .map_err(|error| format!("reading {} failed: {error}", ca.display()))
            .and_then(|pem| {
                CertificateDer::from_pem_slice(pem.as_bytes())
                    .map_err(|error| format!("{} is not a certificate: {error}", ca.display()))?;
                Ok(pem)
            })
            .map_err(|problem| format!("{problem}{}", remedy(dir)))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            ca_pem,
            replaced,
        })
    }

    /// One line saying that this run replaced a kept authority, and why; `None` when
    /// the authority was kept, or there was none to replace.
    pub fn replaced(&self) -> Option<&str> {
        self.replaced.as_deref()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The authority's certificate, as the PEM text a trust store takes.
    #[cfg(test)]
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// The authority's identity: the blake3 of its certificate file.
    pub fn ca_fingerprint(&self) -> String {
        blake3::hash(self.ca_pem.as_bytes()).to_hex().to_string()
    }

    /// The generated `origin_ca.ts` the fixtures import: the authority's certificate,
    /// which a config can't be handed through the environment (its evaluation reads
    /// none).
    pub fn ca_module(&self) -> String {
        format!(
            "// Generated by `cargo xtask differential` — the test CA its https origin is \
             served under.\n\
             export const ORIGIN_CA_PEM = {};\n",
            serde_json::Value::from(self.ca_pem.as_str())
        )
    }

    /// The TLS configuration a server presents the leaf under.
    ///
    /// # Errors
    /// The leaf or its key can't be read, or they are not a usable pair.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        self.kept_server_config()
            .map_err(|problem| format!("{problem}{}", self.remedy()))
    }

    fn kept_server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        let cert = self.dir.join(SERVER_CERT);
        let key = self.dir.join(SERVER_KEY);
        let chain = CertificateDer::pem_file_iter(&cert)
            .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            .map_err(|error| format!("reading {} failed: {error}", cert.display()))?;
        let key_der = PrivateKeyDer::from_pem_file(&key)
            .map_err(|error| format!("reading {} failed: {error}", key.display()))?;
        let config = rustls::ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("configuring TLS failed: {error}"))?
            .with_no_client_auth()
            .with_single_cert(chain, key_der)
            .map_err(|error| {
                format!(
                    "{} and {} are not a usable certificate and key: {error}",
                    cert.display(),
                    key.display()
                )
            })?;
        Ok(Arc::new(config))
    }

    /// The TLS configuration of a client that trusts this authority and no other. It
    /// applies the path validation zap's client applies (zap goes through the platform
    /// verifier, with the system's roots where this one has the authority alone), so a
    /// chain refused here is one zap refuses.
    ///
    /// # Errors
    /// The authority's certificate is not one a client can anchor on.
    pub fn client_config(&self) -> Result<Arc<rustls::ClientConfig>, String> {
        client_config_trusting(&self.ca_pem)
            .map_err(|problem| format!("{problem}{}", self.remedy()))
    }

    /// What to do about a kept PKI that is no use, as the end of a message about it.
    pub fn remedy(&self) -> String {
        remedy(&self.dir)
    }
}

/// A client configuration whose only trust anchor is the certificate in `ca_pem`.
fn client_config_trusting(ca_pem: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    let anchor = CertificateDer::from_pem_slice(ca_pem.as_bytes())
        .map_err(|error| format!("the CA is not a certificate: {error}"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(anchor)
        .map_err(|error| format!("the CA is not a usable trust anchor: {error}"))?;
    let config = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("configuring TLS failed: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The `ring` provider, named per configuration: nothing here depends on a process
/// default being installed.
fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The end of a message about a PKI in `dir` that can't be used as kept: removing the
/// directory is the way out, at the price of every base.
fn remedy(dir: &Path) -> String {
    format!(
        " — remove {} to have it made again (every base is then rebuilt)",
        dir.display()
    )
}

/// The prefix of an issuance's work directory, which its process id follows.
const WORK_PREFIX: &str = ".new-";

/// Remove the work directories earlier issuances left in `dir`: a run killed while
/// issuing leaves one, with a key in it. One whose process is still running — another
/// harness run, issuing now — is left alone. Best-effort.
fn sweep_work_dirs(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|name| name.strip_prefix(WORK_PREFIX))
        else {
            continue;
        };
        let live = pid.parse::<u32>().is_ok_and(|pid| {
            pid != std::process::id() && Path::new("/proc").join(pid.to_string()).exists()
        });
        if !live {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Make `dir` (and what is missing above it), owner-only.
fn make_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)))
        .map_err(|error| format!("making {} private failed: {error}", dir.display()))
}

/// One issuance: `openssl` writing into `work`, each finished file then moved into
/// `dir`.
struct Issuer<'a> {
    dir: &'a Path,
    work: &'a Path,
    openssl: &'a Path,
}

impl Issuer<'_> {
    /// Issue a leaf for `names`, under the kept authority, or under a new one
    /// constrained to `new_ca` when that is given.
    ///
    /// A file that marks a part whole is removed before the part is replaced and
    /// written last — what the authority permits, the leaf's names — so a run cut
    /// short leaves a part that reads as not whole: never a certificate beside
    /// another's key taken as an authority, and never an authority taken as
    /// constrained that isn't. A kept authority's own files stay until the new ones
    /// take their names, so a run that can't make one leaves it as it was, less the
    /// record of what it permits — still an authority the next run replaces.
    fn issue(&self, new_ca: Option<&str>, names: &str) -> Result<(), String> {
        let has_ca = new_ca.is_none();
        self.forget(SERVER_NAMES)?;
        if let Some(permits) = new_ca {
            self.forget(CA_PERMITS)?;
            self.issue_ca(permits).map_err(Failure::into_message)?;
        }
        // a kept authority that can't sign — a certificate beside another's key, a
        // damaged file — is not mended by another run
        self.issue_leaf(names).map_err(|failure| match failure {
            Failure::Failed(problem) if has_ca => format!("{problem}{}", remedy(self.dir)),
            other => other.into_message(),
        })
    }

    fn issue_ca(&self, permits: &str) -> Result<(), Failure> {
        let config = self.write("ca.cnf", &ca_config(permits))?;
        self.openssl(
            "making the test CA",
            &[
                Arg::Text("req"),
                Arg::Text("-x509"),
                Arg::Text("-newkey"),
                Arg::Text("ec"),
                Arg::Text("-pkeyopt"),
                Arg::Text("ec_paramgen_curve:P-256"),
                Arg::Text("-nodes"),
                Arg::Text("-days"),
                Arg::Text(VALID_DAYS),
                Arg::Text("-config"),
                Arg::Path(&config),
                Arg::Text("-keyout"),
                Arg::Path(&self.work.join(CA_KEY)),
                Arg::Text("-out"),
                Arg::Path(&self.work.join(CA_CERT)),
            ],
        )?;
        self.keep(CA_KEY)?;
        self.keep(CA_CERT)?;
        self.write(CA_PERMITS, permits)?;
        self.keep(CA_PERMITS)
    }

    fn issue_leaf(&self, names: &str) -> Result<(), Failure> {
        let config = self.write("leaf.cnf", &leaf_config(names))?;
        let request = self.work.join("server.csr");
        self.openssl(
            "making the server key",
            &[
                Arg::Text("req"),
                Arg::Text("-new"),
                Arg::Text("-newkey"),
                Arg::Text("ec"),
                Arg::Text("-pkeyopt"),
                Arg::Text("ec_paramgen_curve:P-256"),
                Arg::Text("-nodes"),
                Arg::Text("-config"),
                Arg::Path(&config),
                Arg::Text("-keyout"),
                Arg::Path(&self.work.join(SERVER_KEY)),
                Arg::Text("-out"),
                Arg::Path(&request),
            ],
        )?;
        self.openssl(
            "signing the server certificate",
            &[
                Arg::Text("x509"),
                Arg::Text("-req"),
                Arg::Text("-days"),
                Arg::Text(VALID_DAYS),
                Arg::Text("-in"),
                Arg::Path(&request),
                Arg::Text("-CA"),
                Arg::Path(&self.dir.join(CA_CERT)),
                Arg::Text("-CAkey"),
                Arg::Path(&self.dir.join(CA_KEY)),
                Arg::Text("-CAcreateserial"),
                Arg::Text("-CAserial"),
                Arg::Path(&self.work.join("ca.srl")),
                Arg::Text("-extfile"),
                Arg::Path(&config),
                Arg::Text("-extensions"),
                Arg::Text("ext"),
                Arg::Text("-out"),
                Arg::Path(&self.work.join(SERVER_CERT)),
            ],
        )?;
        self.keep(SERVER_KEY)?;
        self.keep(SERVER_CERT)?;
        self.write(SERVER_NAMES, names)?;
        self.keep(SERVER_NAMES)
    }

    /// Run `openssl <args>`; `what` names the step in an error.
    fn openssl(&self, what: &str, args: &[Arg<'_>]) -> Result<(), Failure> {
        let mut command = Command::new(self.openssl);
        for arg in args {
            match arg {
                Arg::Text(text) => command.arg(text),
                Arg::Path(path) => command.arg(path),
            };
        }
        let ran = process::run(command, None, OPENSSL_TIMEOUT).map_err(|error| {
            Failure::NotRun(format!(
                "{what} needs `openssl`, and {} could not be run ({error}): install it — the \
                 harness serves its guests over https under a test CA it keeps in {}",
                self.openssl.display(),
                self.dir.display()
            ))
        })?;
        if ran.success() {
            Ok(())
        } else {
            Err(Failure::Failed(format!(
                "{what} failed: openssl {}",
                ran.describe_failure()
            )))
        }
    }

    /// Write `contents` to `name` in the work directory.
    fn write(&self, name: &str, contents: &str) -> Result<PathBuf, Failure> {
        let path = self.work.join(name);
        std::fs::write(&path, contents).map_err(|error| {
            Failure::NotRun(format!("writing {} failed: {error}", path.display()))
        })?;
        Ok(path)
    }

    /// Move `name` from the work directory into the PKI, owner-only.
    fn keep(&self, name: &str) -> Result<(), Failure> {
        let (from, to) = (self.work.join(name), self.dir.join(name));
        std::fs::set_permissions(&from, std::fs::Permissions::from_mode(0o600))
            .and_then(|()| std::fs::rename(&from, &to))
            .map_err(|error| Failure::NotRun(format!("keeping {} failed: {error}", to.display())))
    }

    /// Remove `name` from the PKI, if it is there.
    fn forget(&self, name: &str) -> Result<(), String> {
        let path = self.dir.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("removing {} failed: {error}", path.display())),
        }
    }
}

/// Why an issuance stopped.
enum Failure {
    /// `openssl` ran and refused: what it was given is the problem.
    Failed(String),
    /// A step never got as far as `openssl`'s answer: no program, or a file that
    /// couldn't be written or kept.
    NotRun(String),
}

impl Failure {
    fn into_message(self) -> String {
        match self {
            Self::Failed(message) | Self::NotRun(message) => message,
        }
    }
}

/// An `openssl` argument: an option or its text, or a path.
enum Arg<'a> {
    Text(&'a str),
    Path(&'a Path),
}

#[cfg(test)]
pub mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{
        CA_CERT, CA_CONFIG, CA_KEY, CA_PERMITS, Issuer, Pki, SERVER_CERT, SERVER_KEY, SERVER_NAMES,
        ca_permits, server_names,
    };

    /// The system `openssl`, or `None` (with a note) where there is none: the tests
    /// that need key material check nothing there.
    pub fn openssl() -> Option<PathBuf> {
        let found = Command::new("openssl")
            .arg("version")
            .output()
            .is_ok_and(|output| output.status.success());
        if !found {
            eprintln!("skipped: no `openssl` on PATH");
        }
        found.then(|| PathBuf::from("openssl"))
    }

    /// A program that is not there: a PKI read through it ran no `openssl`.
    const NO_OPENSSL: &str = "/nonexistent/zap-differential/openssl";

    /// `openssl x509 -noout -text` of `file`.
    fn text_of(file: &Path) -> String {
        let output = Command::new("openssl")
            .args(["x509", "-noout", "-text", "-in"])
            .arg(file)
            .output()
            .expect("openssl runs");
        assert!(output.status.success(), "{}", file.display());
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
    }

    const FILES: [&str; 6] = [
        CA_CERT,
        CA_KEY,
        CA_PERMITS,
        SERVER_CERT,
        SERVER_KEY,
        SERVER_NAMES,
    ];

    /// A PKI whose leaf is for `names`, signed by `pki`'s own authority key whatever
    /// that authority permits: what holding the key lets anyone make. In `dir`.
    pub fn leaf_signed_for(pki: &Pki, dir: &Path, openssl: &Path, names: &str) -> Pki {
        let work = dir.join("work");
        std::fs::create_dir_all(&work).expect("mkdir");
        for file in [CA_CERT, CA_KEY] {
            std::fs::copy(pki.dir().join(file), dir.join(file)).expect("copy");
        }
        let issued = Issuer {
            dir,
            work: &work,
            openssl,
        }
        .issue_leaf(names);
        assert!(issued.is_ok(), "a leaf for {names}");
        std::fs::remove_dir_all(&work).expect("remove");
        Pki {
            dir: dir.to_path_buf(),
            ca_pem: pki.ca_pem().to_owned(),
            replaced: None,
        }
    }

    /// An authority as one made with no name constraints is kept: its certificate and
    /// key, and no record of what it permits.
    fn unconstrained_authority(dir: &Path) {
        std::fs::create_dir_all(dir).expect("mkdir");
        let config = dir.join("old.cnf");
        std::fs::write(&config, CA_CONFIG).expect("write");
        let made = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "ec", "-pkeyopt"])
            .args([
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "30",
                "-config",
            ])
            .arg(&config)
            .arg("-keyout")
            .arg(dir.join(CA_KEY))
            .arg("-out")
            .arg(dir.join(CA_CERT))
            .output()
            .expect("openssl runs");
        assert!(made.status.success(), "{made:?}");
        std::fs::remove_file(config).expect("remove");
    }

    /// `openssl verify` of `leaf` under `ca`: whether it passed, and what it said.
    pub fn openssl_verify(ca: &Path, leaf: &Path) -> (bool, String) {
        let output = Command::new("openssl")
            .arg("verify")
            .arg("-CAfile")
            .arg(ca)
            .arg(leaf)
            .output()
            .expect("openssl runs");
        (
            output.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    }

    fn contents(dir: &Path) -> Vec<Vec<u8>> {
        FILES
            .iter()
            .map(|file| std::fs::read(dir.join(file)).expect("read"))
            .collect()
    }

    #[test]
    fn the_names_cover_the_gateway_and_this_machine() {
        assert_eq!(
            server_names(),
            ["IP:192.168.122.1", "IP:127.0.0.1", "DNS:localhost"]
        );
    }

    /// A first run makes an authority and a leaf under it, owner-only; the authority is
    /// one (`CA:TRUE`), the leaf is not (`CA:FALSE`) and names what was asked.
    #[test]
    fn a_first_run_makes_an_authority_and_a_leaf() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("cache").join("pki");
        let pki = Pki::ensure(&dir, &openssl, &server_names()).expect("ensure");

        assert_eq!(mode_of(&dir), 0o700);
        for file in FILES {
            assert_eq!(mode_of(&dir.join(file)), 0o600, "{file}");
        }
        let left: Vec<_> = std::fs::read_dir(&dir)
            .expect("read_dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(left.len(), FILES.len(), "{left:?}");

        let ca = text_of(&dir.join(CA_CERT));
        assert!(ca.contains("CA:TRUE"), "{ca}");
        assert!(ca.contains("Certificate Sign"), "{ca}");
        let leaf = text_of(&dir.join(SERVER_CERT));
        assert!(leaf.contains("CA:FALSE"), "{leaf}");
        assert!(leaf.contains("TLS Web Server Authentication"), "{leaf}");
        assert!(
            leaf.contains("IP Address:192.168.122.1, IP Address:127.0.0.1, DNS:localhost"),
            "{leaf}"
        );
        let verified = Command::new("openssl")
            .arg("verify")
            .arg("-CAfile")
            .arg(dir.join(CA_CERT))
            .arg(dir.join(SERVER_CERT))
            .output()
            .expect("openssl runs");
        assert!(verified.status.success(), "the leaf chains to the CA");

        assert_eq!(pki.replaced(), None);

        assert!(pki.ca_pem().starts_with("-----BEGIN CERTIFICATE-----\n"));
        // the fixtures mark the CA in a trust bundle by a whole 64-character body line
        let base64 = |line: &str| {
            line.len() == 64
                && line
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        };
        assert!(pki.ca_pem().lines().any(base64), "{}", pki.ca_pem());
        assert_eq!(pki.ca_fingerprint().len(), 64);
        assert_eq!(pki.dir(), dir);
        pki.server_config().expect("a server config");
        pki.client_config().expect("a client config");
    }

    /// What is kept is reused byte for byte, with no `openssl` at all.
    #[test]
    fn a_kept_pki_is_reused_without_openssl() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        let first = Pki::ensure(&dir, &openssl, &server_names()).expect("ensure");
        let before = contents(&dir);
        let again = Pki::ensure(&dir, Path::new(NO_OPENSSL), &server_names()).expect("reuse");
        assert_eq!(contents(&dir), before);
        assert_eq!(again.ca_pem(), first.ca_pem());
        assert_eq!(again.ca_fingerprint(), first.ca_fingerprint());
    }

    /// Other names get a new authority, constrained to them, and a leaf under it: an
    /// authority vouches for the names it was made for and no others. A leaf that is
    /// missing is made again under the kept authority; a missing authority gets a new
    /// one, and a leaf with it.
    #[test]
    fn a_part_that_is_missing_or_stale_is_made_again() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        let first = Pki::ensure(&dir, &openssl, &server_names()).expect("ensure");
        let leaf = std::fs::read(dir.join(SERVER_CERT)).expect("read");

        let other = ["IP:127.0.0.1".to_owned(), "DNS:other.test".to_owned()];
        let renamed = Pki::ensure(&dir, &openssl, &other).expect("reissue");
        assert_ne!(renamed.ca_fingerprint(), first.ca_fingerprint());
        assert_eq!(
            renamed.replaced(),
            Some(
                format!(
                    "the test CA kept in {} was not constrained to IP:127.0.0.1,DNS:other.test: \
                     a new one is made, and every base is rebuilt",
                    dir.display()
                )
                .as_str()
            )
        );
        assert_ne!(std::fs::read(dir.join(SERVER_CERT)).expect("read"), leaf);
        assert!(text_of(&dir.join(SERVER_CERT)).contains("DNS:other.test"));
        assert_eq!(
            std::fs::read_to_string(dir.join(SERVER_NAMES)).expect("read"),
            "IP:127.0.0.1,DNS:other.test"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join(CA_PERMITS)).expect("read"),
            "permitted;IP:127.0.0.1/255.255.255.255,permitted;DNS:other.test"
        );
        let ca = text_of(&dir.join(CA_CERT));
        assert!(ca.contains("DNS:other.test"), "{ca}");
        assert!(!ca.contains("192.168.122.1"), "{ca}");
        assert!(openssl_verify(&dir.join(CA_CERT), &dir.join(SERVER_CERT)).0);

        // a leaf cut short of its names file is not whole, and is made under the
        // authority that is kept
        std::fs::remove_file(dir.join(SERVER_NAMES)).expect("remove");
        let missing = Pki::ensure(&dir, Path::new(NO_OPENSSL), &other).expect_err("no openssl");
        assert!(missing.contains("making the server key needs `openssl`"));
        let mended = Pki::ensure(&dir, &openssl, &other).expect("a new leaf");
        assert_eq!(mended.ca_fingerprint(), renamed.ca_fingerprint());
        assert_eq!(mended.replaced(), None);

        std::fs::remove_file(dir.join(CA_CERT)).expect("remove");
        let fresh = Pki::ensure(&dir, &openssl, &other).expect("a new authority");
        assert_ne!(fresh.ca_fingerprint(), renamed.ca_fingerprint());
        // there was no authority to replace
        assert_eq!(fresh.replaced(), None);
        assert!(text_of(&dir.join(SERVER_CERT)).contains("DNS:other.test"));
    }

    /// What an authority is permitted is each name of its leaf and nothing else, and a
    /// list that would leave a kind of name open is refused.
    #[test]
    fn the_permitted_names_are_the_leafs_own() {
        assert_eq!(
            ca_permits(&server_names()).as_deref(),
            Ok("permitted;IP:192.168.122.1/255.255.255.255,\
                permitted;IP:127.0.0.1/255.255.255.255,permitted;DNS:localhost")
        );
        assert_eq!(
            ca_permits(&["IP:::1".to_owned(), "DNS:a.b-c.test".to_owned()]).as_deref(),
            Ok("permitted;IP:::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,\
                permitted;DNS:a.b-c.test")
        );
        for (names, problem) in [
            (
                vec!["IP:127.0.0.1"],
                "IP:127.0.0.1 holds no DNS name, which would leave every one open",
            ),
            (
                vec!["DNS:localhost"],
                "DNS:localhost holds no address, which would leave every one open",
            ),
            (
                vec![],
                " holds no DNS name, which would leave every one open",
            ),
            (
                vec!["IP:127.0.0.1", "DNS:localhost", "email:a@b.test"],
                "can't be held to email:a@b.test",
            ),
            (
                vec!["IP:localhost", "DNS:localhost"],
                "can't be held to IP:localhost",
            ),
            (
                vec!["IP:127.0.0.1/8", "DNS:localhost"],
                "can't be held to IP:127.0.0.1/8",
            ),
            (
                vec!["IP:127.0.0.1", "DNS:localhost,permitted;DNS:test"],
                "can't be held to DNS:localhost,permitted;DNS:test",
            ),
            (vec!["IP:127.0.0.1", "DNS:"], "can't be held to DNS:"),
            (
                vec!["IP:127.0.0.1", "DNS:.test"],
                "can't be held to DNS:.test",
            ),
            (
                vec!["IP:127.0.0.1", "DNS:a\nb"],
                "can't be held to DNS:a\nb",
            ),
        ] {
            let names: Vec<String> = names.into_iter().map(str::to_owned).collect();
            let error = ca_permits(&names).expect_err("a refusal");
            assert!(error.contains(problem), "{names:?}: {error}");
            // nothing is made for a list that is refused
            let scratch = tempfile::tempdir().expect("tempdir");
            let dir = scratch.path().join("pki");
            assert_eq!(
                Pki::ensure(&dir, Path::new(NO_OPENSSL), &names).expect_err("a refusal"),
                error
            );
            assert!(!dir.exists());
        }
    }

    /// The authority's certificate says what it permits, critically: the gateway and
    /// loopback, each alone, and `localhost`. Its own leaf passes under it, and a leaf
    /// its key signs for a name outside them does not.
    #[test]
    fn the_authority_is_constrained_to_the_names_it_serves() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        let pki = Pki::ensure(&dir, &openssl, &server_names()).expect("ensure");
        let ca = text_of(&dir.join(CA_CERT));
        let Some((_, constraints)) = ca.split_once("X509v3 Name Constraints: critical\n") else {
            panic!("critical name constraints: {ca}");
        };
        let permitted: Vec<&str> = constraints
            .lines()
            .map(str::trim)
            .skip_while(|line| *line != "Permitted:")
            .skip(1)
            .take_while(|line| line.starts_with("IP:") || line.starts_with("DNS:"))
            .collect();
        assert_eq!(
            permitted,
            [
                "IP:192.168.122.1/255.255.255.255",
                "IP:127.0.0.1/255.255.255.255",
                "DNS:localhost"
            ],
            "{ca}"
        );
        assert!(!ca.contains("Excluded:"), "{ca}");
        assert_eq!(
            std::fs::read_to_string(dir.join(CA_PERMITS)).expect("read"),
            ca_permits(&server_names()).expect("permits")
        );
        assert!(openssl_verify(&dir.join(CA_CERT), &dir.join(SERVER_CERT)).0);

        for names in [
            "IP:127.0.0.1,DNS:example.com",
            "IP:127.0.0.1,IP:10.0.0.1",
            "IP:192.168.122.2",
            "IP:127.0.0.1,IP:::1",
            "DNS:example.com",
        ] {
            let rogue_dir = scratch.path().join(names.replace([':', ','], "_"));
            let rogue = leaf_signed_for(&pki, &rogue_dir, &openssl, names);
            let (passed, said) = openssl_verify(&dir.join(CA_CERT), &rogue.dir().join(SERVER_CERT));
            assert!(!passed, "{names}: {said}");
            assert!(
                said.contains("permitted subtree violation"),
                "{names}: {said}"
            );
        }
        // a name under a permitted DNS name is permitted with it
        let under = leaf_signed_for(
            &pki,
            &scratch.path().join("under"),
            &openssl,
            "IP:127.0.0.1,DNS:a.localhost",
        );
        assert!(openssl_verify(&dir.join(CA_CERT), &under.dir().join(SERVER_CERT)).0);
    }

    /// A kept authority with no record of what it permits is replaced, with a line saying so, and so is the
    /// leaf: the new authority's fingerprint is another, and it is constrained.
    #[test]
    fn a_kept_authority_with_no_constraints_is_replaced() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        unconstrained_authority(&dir);
        let old = std::fs::read_to_string(dir.join(CA_CERT)).expect("read");
        assert!(!text_of(&dir.join(CA_CERT)).contains("Name Constraints"));
        // with a leaf of its own, whole
        let names = server_names().join(",");
        let old_pki = Pki {
            dir: dir.clone(),
            ca_pem: old.clone(),
            replaced: None,
        };
        let work = scratch.path().join("old-leaf");
        leaf_signed_for(&old_pki, &work, &openssl, &names);
        for file in [SERVER_CERT, SERVER_KEY, SERVER_NAMES] {
            std::fs::copy(work.join(file), dir.join(file)).expect("copy");
        }

        let pki = Pki::ensure(&dir, &openssl, &server_names()).expect("replaced");
        assert_eq!(
            pki.replaced(),
            Some(
                format!(
                    "the test CA kept in {} was not constrained to {names}: a new one is made, \
                     and every base is rebuilt",
                    dir.display()
                )
                .as_str()
            )
        );
        assert_ne!(pki.ca_pem(), old);
        assert_ne!(
            pki.ca_fingerprint(),
            blake3::hash(old.as_bytes()).to_hex().to_string()
        );
        assert!(text_of(&dir.join(CA_CERT)).contains("X509v3 Name Constraints: critical"));
        assert!(openssl_verify(&dir.join(CA_CERT), &dir.join(SERVER_CERT)).0);
        // and it is kept from then on
        let again = Pki::ensure(&dir, Path::new(NO_OPENSSL), &server_names()).expect("reuse");
        assert_eq!(again.ca_fingerprint(), pki.ca_fingerprint());
        assert_eq!(again.replaced(), None);

        // replacing one takes `openssl`: nothing kept is taken as it is, and a run that
        // can't replace it leaves it as it was — an authority with no record of what
        // it permits, which the next run replaces and says so
        let other = scratch.path().join("other");
        unconstrained_authority(&other);
        let kept = |file: &str| std::fs::read(other.join(file)).expect("read");
        let (old_cert, old_key) = (kept(CA_CERT), kept(CA_KEY));
        for unusable in [Path::new(NO_OPENSSL), Path::new("false")] {
            let error = Pki::ensure(&other, unusable, &server_names()).expect_err("no new CA");
            assert!(error.starts_with("making the test CA "), "{error}");
            assert_eq!(
                (kept(CA_CERT), kept(CA_KEY)),
                (old_cert.clone(), old_key.clone())
            );
            assert!(!other.join(CA_PERMITS).exists());
        }
        let replaced = Pki::ensure(&other, &openssl, &server_names()).expect("replaced");
        assert!(replaced.replaced().is_some());
        assert_ne!(kept(CA_CERT), old_cert);
        assert!(text_of(&other.join(CA_CERT)).contains("X509v3 Name Constraints: critical"));
    }

    /// A constrained authority that a run fails to replace is no longer taken as
    /// constrained to anything: the record of what it permits goes before the first
    /// step, so the next run makes a new one whatever names it asks for.
    #[test]
    fn a_failed_replacement_leaves_no_authority_taken_as_constrained() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        let first = Pki::ensure(&dir, &openssl, &server_names()).expect("ensure");
        let other = ["IP:127.0.0.1".to_owned(), "DNS:other.test".to_owned()];
        let error = Pki::ensure(&dir, Path::new("false"), &other).expect_err("a failed step");
        assert!(
            error.starts_with("making the test CA failed: openssl exit 1"),
            "{error}"
        );
        assert!(!dir.join(CA_PERMITS).exists());
        assert!(!dir.join(SERVER_NAMES).exists());
        for names in [&server_names()[..], &other[..]] {
            let error = Pki::ensure(&dir, Path::new(NO_OPENSSL), names).expect_err("not reused");
            assert!(
                error.starts_with("making the test CA needs `openssl`"),
                "{error}"
            );
        }
        let again = Pki::ensure(&dir, &openssl, &server_names()).expect("made again");
        assert_ne!(again.ca_fingerprint(), first.ca_fingerprint());
        assert!(again.replaced().is_some());
        assert!(openssl_verify(&dir.join(CA_CERT), &dir.join(SERVER_CERT)).0);
    }

    /// With no `openssl` and nothing kept, the run stops and says what it needs.
    #[test]
    fn a_missing_openssl_is_named() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        let error =
            Pki::ensure(&dir, Path::new(NO_OPENSSL), &server_names()).expect_err("no openssl");
        assert!(
            error.starts_with(&format!(
                "making the test CA needs `openssl`, and {NO_OPENSSL} could not be run ("
            )),
            "{error}"
        );
        assert!(error.contains("install it"), "{error}");
        assert!(error.ends_with(&dir.display().to_string()), "{error}");
        // nothing half-made is left to be taken for a PKI
        assert!(!dir.join(CA_CERT).exists());
        assert!(!dir.join(format!(".new-{}", std::process::id())).exists());
    }

    /// The generated module is a string a config evaluates back to the certificate.
    #[test]
    fn the_generated_module_carries_the_certificate() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let pki = Pki::ensure(scratch.path(), &openssl, &server_names()).expect("ensure");
        let module = pki.ca_module();
        let literal = module
            .lines()
            .find_map(|line| line.strip_prefix("export const ORIGIN_CA_PEM = "))
            .and_then(|rest| rest.strip_suffix(';'))
            .expect("the export");
        let parsed: String = serde_json::from_str(literal).expect("a string literal");
        assert_eq!(parsed, pki.ca_pem());
    }

    /// An issuance cut short leaves the part it was replacing reading as missing: the
    /// file that marks a part whole goes before the part is touched, so a later run
    /// makes it again and never pairs a kept certificate with another's key.
    #[test]
    fn an_issuance_cut_short_leaves_the_part_missing() {
        let Some(openssl) = openssl() else { return };
        // a program that runs and fails: an `openssl` stopped at its first step
        let failing = Path::new("false");
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        let first = Pki::ensure(&dir, &openssl, &server_names()).expect("ensure");

        // an authority whose key is gone is made again, and the leaf with it
        std::fs::remove_file(dir.join(CA_KEY)).expect("remove");
        let error = Pki::ensure(&dir, failing, &server_names()).expect_err("a failed step");
        assert!(
            error.starts_with("making the test CA failed: openssl exit 1"),
            "{error}"
        );
        assert!(
            !dir.join(CA_PERMITS).exists(),
            "the old authority reads as not whole"
        );
        // its certificate with no key is no authority: nothing is reused
        let error =
            Pki::ensure(&dir, Path::new(NO_OPENSSL), &server_names()).expect_err("not reused");
        assert!(
            error.starts_with("making the test CA needs `openssl`"),
            "{error}"
        );
        assert!(
            !dir.join(SERVER_NAMES).exists(),
            "the old leaf reads as gone"
        );
        assert!(!dir.join(format!(".new-{}", std::process::id())).exists());

        let fresh = Pki::ensure(&dir, &openssl, &server_names()).expect("made again");
        assert_ne!(fresh.ca_fingerprint(), first.ca_fingerprint());
        let verified = Command::new("openssl")
            .arg("verify")
            .arg("-CAfile")
            .arg(dir.join(CA_CERT))
            .arg(dir.join(SERVER_CERT))
            .output()
            .expect("openssl runs");
        assert!(
            verified.status.success(),
            "the new leaf chains to the new CA"
        );
    }

    /// A work directory a killed run left is swept by the next run, kept or not; one
    /// whose process is still running is another run's, and stays.
    #[test]
    fn a_stale_work_directory_is_swept() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        Pki::ensure(&dir, &openssl, &server_names()).expect("ensure");
        // no process has this id: it is past the kernel's largest
        let stale = dir.join(".new-4294967295");
        let ours = dir.join(format!(".new-{}", std::process::id()));
        // the test runner's parent is running for as long as this test is
        let live = dir.join(format!(".new-{}", std::os::unix::process::parent_id()));
        for work in [&stale, &ours, &live] {
            std::fs::create_dir(work).expect("mkdir");
            std::fs::write(work.join(SERVER_KEY), "a key").expect("write");
        }
        let unrelated = dir.join(".newer");
        std::fs::write(&unrelated, "").expect("write");
        // nothing to issue: the sweep is the run's own, not the issuance's
        Pki::ensure(&dir, Path::new(NO_OPENSSL), &server_names()).expect("reuse");
        assert!(!stale.exists());
        assert!(!ours.exists());
        assert!(live.exists());
        assert!(unrelated.exists());
    }

    /// A kept PKI that is no use says so with the way out: a certificate that isn't
    /// one, a leaf beside another's key, an authority that can't sign.
    #[test]
    fn a_kept_pki_that_is_no_use_names_the_remedy() {
        let Some(openssl) = openssl() else { return };
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        let other = scratch.path().join("other");
        let remedy = format!(
            " — remove {} to have it made again (every base is then rebuilt)",
            dir.display()
        );
        let pki = Pki::ensure(&dir, &openssl, &server_names()).expect("ensure");
        Pki::ensure(&other, &openssl, &server_names()).expect("another");
        assert_eq!(pki.remedy(), remedy);

        // a leaf beside another's key
        let own_key = std::fs::read(dir.join(SERVER_KEY)).expect("read");
        std::fs::copy(other.join(SERVER_KEY), dir.join(SERVER_KEY)).expect("copy");
        let error = pki.server_config().expect_err("a mismatched pair");
        assert!(
            error.contains("are not a usable certificate and key"),
            "{error}"
        );
        assert!(error.ends_with(&remedy), "{error}");
        std::fs::write(dir.join(SERVER_KEY), "not a key\n").expect("write");
        let error = pki.server_config().expect_err("no key");
        assert!(error.ends_with(&remedy), "{error}");
        std::fs::write(dir.join(SERVER_KEY), own_key).expect("write");
        pki.server_config().expect("the pair again");

        // an authority's certificate beside another's key signs nothing a client takes
        std::fs::copy(other.join(CA_KEY), dir.join(CA_KEY)).expect("copy");
        std::fs::remove_file(dir.join(SERVER_NAMES)).expect("remove");
        let error = Pki::ensure(&dir, &openssl, &server_names()).expect_err("a mismatched CA");
        assert!(
            error.starts_with("signing the server certificate failed: openssl "),
            "{error}"
        );
        assert!(error.ends_with(&remedy), "{error}");
        // with no `openssl` the remedy is `openssl`, not the directory
        let error =
            Pki::ensure(&dir, Path::new(NO_OPENSSL), &server_names()).expect_err("no openssl");
        assert!(!error.contains("remove "), "{error}");

        // a certificate that isn't one
        let scratch = tempfile::tempdir().expect("tempdir");
        let dir = scratch.path().join("pki");
        Pki::ensure(&dir, &openssl, &server_names()).expect("ensure");
        std::fs::write(dir.join(CA_CERT), "not a certificate\n").expect("write");
        let error = Pki::ensure(&dir, &openssl, &server_names()).expect_err("no certificate");
        assert!(error.contains("ca.crt is not a certificate"), "{error}");
        assert!(error.ends_with("(every base is then rebuilt)"), "{error}");
    }
}
