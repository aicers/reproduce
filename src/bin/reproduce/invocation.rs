//! Command-line invocation: local mode (`reproduce <CONFIG>`) and remote mode
//! (`reproduce --cert … --key … --ca-certs … --state-dir … <MANAGER>`).

use std::fs::{DirBuilder, OpenOptions};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

const CERT_FLAG: &str = "--cert";
const KEY_FLAG: &str = "--key";
const CA_CERTS_FLAG: &str = "--ca-certs";
const STATE_DIR_FLAG: &str = "--state-dir";
const MANAGER_FORM: &str = "<server_name>@<ip>:<port>";

/// What the command line asks for.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Invocation {
    Help,
    Version,
    /// Local mode: read the configuration from a file.
    Local(PathBuf),
    /// Remote mode: take the configuration from the Central Manager.
    Remote(RemoteArgs),
}

/// The arguments of a remote-mode invocation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RemoteArgs {
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
    pub(crate) ca_certs: Vec<PathBuf>,
    pub(crate) state_dir: PathBuf,
    pub(crate) manager: Manager,
}

/// The Central Manager endpoint, written as `<server_name>@<ip>:<port>`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Manager {
    pub(crate) server_name: String,
    pub(crate) addr: SocketAddr,
}

/// Parses the command-line arguments, excluding the program name.
///
/// # Errors
///
/// Returns the reason an invocation is refused.
pub(crate) fn parse_args(args: &[String]) -> Result<Invocation, String> {
    match args {
        [] => return Err("insufficient arguments".to_string()),
        [arg] if arg == "-h" || arg == "--help" => return Ok(Invocation::Help),
        [arg] if arg == "-V" || arg == "--version" => return Ok(Invocation::Version),
        _ => {}
    }

    let mut cert = None;
    let mut key = None;
    let mut ca_certs = None;
    let mut state_dir = None;
    let mut positionals = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if !arg.starts_with('-') {
            positionals.push(arg);
            continue;
        }
        let slot = match arg.as_str() {
            CERT_FLAG => &mut cert,
            KEY_FLAG => &mut key,
            CA_CERTS_FLAG => &mut ca_certs,
            STATE_DIR_FLAG => &mut state_dir,
            _ => return Err(format!("unknown flag {arg}")),
        };
        if slot.is_some() {
            return Err(format!("flag {arg} is repeated"));
        }
        let Some(value) = iter.next().filter(|value| !value.starts_with('-')) else {
            return Err(format!("flag {arg} is missing its value"));
        };
        if arg == CA_CERTS_FLAG {
            parse_ca_certs(value)?;
        } else if value.is_empty() {
            return Err(format!("flag {arg} has an empty value"));
        }
        *slot = Some(value);
    }

    if positionals.len() > 1 {
        return Err("too many arguments".to_string());
    }
    let positional = positionals.first();
    let any_flag = cert.is_some() || key.is_some() || ca_certs.is_some() || state_dir.is_some();
    if !any_flag {
        // Without flags, every argument is positional, so there is one.
        let Some(config) = positional else {
            return Err("insufficient arguments".to_string());
        };
        return Ok(Invocation::Local(PathBuf::from(config)));
    }

    let manager = positional
        .map(|arg| {
            parse_manager(arg).map_err(|reason| {
                format!(
                    "\"{arg}\" is not a manager endpoint {MANAGER_FORM} ({reason}); a \
                     configuration path cannot be combined with flags"
                )
            })
        })
        .transpose()?;
    let required = |value: Option<&String>, flag: &str| {
        value.cloned().ok_or_else(|| format!("missing flag {flag}"))
    };
    let cert = required(cert, CERT_FLAG)?;
    let key = required(key, KEY_FLAG)?;
    let ca_certs = parse_ca_certs(&required(ca_certs, CA_CERTS_FLAG)?)?;
    let state_dir = required(state_dir, STATE_DIR_FLAG)?;
    let Some(manager) = manager else {
        return Err(format!("missing the manager endpoint {MANAGER_FORM}"));
    };

    Ok(Invocation::Remote(RemoteArgs {
        cert: PathBuf::from(cert),
        key: PathBuf::from(key),
        ca_certs,
        state_dir: PathBuf::from(state_dir),
        manager,
    }))
}

/// Splits a `--ca-certs` value at `,`, keeping each entry verbatim.
fn parse_ca_certs(value: &str) -> Result<Vec<PathBuf>, String> {
    let paths: Vec<PathBuf> = value.split(',').map(PathBuf::from).collect();
    if paths.iter().any(|path| path.as_os_str().is_empty()) {
        return Err(format!(
            "invalid {CA_CERTS_FLAG} list \"{value}\": an entry is empty"
        ));
    }
    Ok(paths)
}

/// Parses `<server_name>@<ip>:<port>`, splitting at the first `@`.
fn parse_manager(arg: &str) -> Result<Manager, String> {
    let Some((server_name, addr)) = arg.split_once('@') else {
        return Err("no @".to_string());
    };
    if server_name.is_empty() {
        return Err("empty server name".to_string());
    }
    let addr = addr
        .parse()
        .map_err(|error| format!("invalid address \"{addr}\": {error}"))?;
    Ok(Manager {
        server_name: server_name.to_string(),
        addr,
    })
}

/// Resolves the state directory against the working directory, creates it
/// with mode 0700 when missing, and checks that it is writable.
///
/// An existing directory is used as it is; its mode is not changed.
///
/// # Errors
///
/// Returns an error if the directory cannot be created, the path exists and
/// is not a directory, or a file cannot be created and removed in it.
pub(crate) fn prepare_state_dir(state_dir: &Path) -> Result<PathBuf> {
    let state_dir = std::env::current_dir()
        .context("cannot read the working directory")?
        .join(state_dir);
    match std::fs::metadata(&state_dir) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => bail!(
            "the state directory {} is not a directory",
            state_dir.display()
        ),
        // A path that cannot be inspected is created; that reports why it is
        // unusable, such as a missing permission or a file in its parents.
        Err(_) => {
            let mut builder = DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder.create(&state_dir).with_context(|| {
                format!("cannot create the state directory {}", state_dir.display())
            })?;
        }
    }

    let check = state_dir.join(format!(".write-check-{}", std::process::id()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&check)
        .and_then(|_| std::fs::remove_file(&check))
        .with_context(|| {
            format!(
                "the state directory {} is not writable",
                state_dir.display()
            )
        })?;
    Ok(state_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REMOTE: [&str; 9] = [
        "--cert",
        "cert.pem",
        "--key",
        "key.pem",
        "--ca-certs",
        "root.pem,other root.pem",
        "--state-dir",
        "state",
        "manager@127.0.0.1:38390",
    ];

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    fn refusal(arguments: &[&str]) -> String {
        parse_args(&args(arguments)).expect_err("invocation should be refused")
    }

    fn remote(arguments: &[&str]) -> RemoteArgs {
        match parse_args(&args(arguments)) {
            Ok(Invocation::Remote(remote)) => remote,
            other => panic!("expected a remote invocation, got {other:?}"),
        }
    }

    /// Returns `REMOTE` with `flag` and its value removed.
    fn without(flag: &str) -> Vec<&'static str> {
        let index = REMOTE
            .iter()
            .position(|arg| *arg == flag)
            .expect("flag is in REMOTE");
        REMOTE
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index && *i != index + 1)
            .map(|(_, arg)| *arg)
            .collect()
    }

    #[test]
    fn help_and_version_as_sole_argument() {
        for arg in ["-h", "--help"] {
            assert_eq!(parse_args(&args(&[arg])), Ok(Invocation::Help));
        }
        for arg in ["-V", "--version"] {
            assert_eq!(parse_args(&args(&[arg])), Ok(Invocation::Version));
        }
    }

    #[test]
    fn help_and_version_next_to_other_arguments_are_unknown_flags() {
        for flag in ["-h", "--help", "-V", "--version"] {
            assert_eq!(
                refusal(&["config.toml", flag]),
                format!("unknown flag {flag}")
            );
            assert_eq!(
                refusal(&[flag, "config.toml"]),
                format!("unknown flag {flag}")
            );
            let mut arguments = REMOTE.to_vec();
            arguments.push(flag);
            assert_eq!(refusal(&arguments), format!("unknown flag {flag}"));
        }
    }

    #[test]
    fn local_mode_takes_one_positional_argument() {
        assert_eq!(
            parse_args(&args(&["config.toml"])),
            Ok(Invocation::Local(PathBuf::from("config.toml")))
        );
        assert_eq!(
            parse_args(&args(&["./-name.toml"])),
            Ok(Invocation::Local(PathBuf::from("./-name.toml")))
        );
        assert!(refusal(&[]).contains("insufficient arguments"));
        assert!(refusal(&["one", "two"]).contains("too many arguments"));
        assert!(refusal(&["one", "two", "three"]).contains("too many arguments"));
    }

    #[test]
    fn local_path_starting_with_dash_is_a_flag() {
        assert_eq!(refusal(&["-name.toml"]), "unknown flag -name.toml");
    }

    #[test]
    fn remote_mode_parses_all_flags() {
        let remote = remote(&REMOTE);
        assert_eq!(
            remote,
            RemoteArgs {
                cert: PathBuf::from("cert.pem"),
                key: PathBuf::from("key.pem"),
                ca_certs: vec![PathBuf::from("root.pem"), PathBuf::from("other root.pem")],
                state_dir: PathBuf::from("state"),
                manager: Manager {
                    server_name: "manager".to_string(),
                    addr: "127.0.0.1:38390".parse().expect("address"),
                },
            }
        );
    }

    #[test]
    fn remote_flags_and_manager_in_any_order() {
        let expected = remote(&REMOTE);
        let mut reordered = REMOTE.to_vec();
        reordered.rotate_right(1);
        assert_eq!(remote(&reordered), expected);
        let reordered = [
            "--state-dir",
            "state",
            "--ca-certs",
            "root.pem,other root.pem",
            "manager@127.0.0.1:38390",
            "--key",
            "key.pem",
            "--cert",
            "cert.pem",
        ];
        assert_eq!(remote(&reordered), expected);
    }

    #[test]
    fn manager_endpoint_forms() {
        let mut arguments = REMOTE.to_vec();
        arguments[8] = "name@[::1]:38390";
        let remote_args = remote(&arguments);
        assert_eq!(remote_args.manager.server_name, "name");
        assert_eq!(
            remote_args.manager.addr,
            "[::1]:38390".parse().expect("address")
        );

        arguments[8] = "a@b@10.0.0.1:1";
        let error = refusal(&arguments);
        assert!(error.contains("not a manager endpoint"), "{error}");

        arguments[8] = "name@manager.example:38390";
        let error = refusal(&arguments);
        assert!(error.contains("not a manager endpoint"), "{error}");

        for manager in [
            "@127.0.0.1:38390",
            "127.0.0.1:38390",
            "name@127.0.0.1",
            "name@::1:38390",
            "name@",
        ] {
            arguments[8] = manager;
            let error = refusal(&arguments);
            assert!(
                error.contains("not a manager endpoint"),
                "{manager}: {error}"
            );
        }
    }

    #[test]
    fn unknown_and_repeated_flags_are_refused() {
        let mut arguments = REMOTE.to_vec();
        arguments[0] = "--cert=cert.pem";
        arguments.remove(1);
        assert_eq!(refusal(&arguments), "unknown flag --cert=cert.pem");

        let mut arguments = REMOTE.to_vec();
        arguments.extend(["--key", "other.pem"]);
        assert_eq!(refusal(&arguments), "flag --key is repeated");

        let mut arguments = REMOTE.to_vec();
        arguments.push("--");
        assert_eq!(refusal(&arguments), "unknown flag --");
    }

    #[test]
    fn flag_without_value_is_refused() {
        let mut arguments = without("--state-dir");
        arguments.push("--state-dir");
        assert_eq!(refusal(&arguments), "flag --state-dir is missing its value");

        let mut arguments = REMOTE.to_vec();
        arguments[1] = "--key";
        assert_eq!(refusal(&arguments), "flag --cert is missing its value");

        let mut arguments = REMOTE.to_vec();
        arguments[1] = "-cert.pem";
        assert_eq!(refusal(&arguments), "flag --cert is missing its value");
    }

    #[test]
    fn empty_values_are_refused() {
        for index in [1, 3, 7] {
            let mut arguments = REMOTE.to_vec();
            arguments[index] = "";
            assert_eq!(
                refusal(&arguments),
                format!("flag {} has an empty value", REMOTE[index - 1])
            );
        }
    }

    #[test]
    fn ca_certs_list_is_split_verbatim_and_refuses_empty_entries() {
        let mut arguments = REMOTE.to_vec();
        arguments[5] = " a.pem , b.pem";
        assert_eq!(
            remote(&arguments).ca_certs,
            vec![PathBuf::from(" a.pem "), PathBuf::from(" b.pem")]
        );

        for list in ["", ",", "a.pem,", ",a.pem", "a.pem,,b.pem"] {
            arguments[5] = list;
            let error = refusal(&arguments);
            assert!(
                error.contains("invalid --ca-certs list"),
                "{list:?}: {error}"
            );
        }
    }

    #[test]
    fn missing_flags_and_manager_are_refused() {
        for flag in ["--cert", "--key", "--ca-certs", "--state-dir"] {
            assert_eq!(refusal(&without(flag)), format!("missing flag {flag}"));
        }
        let error = refusal(&REMOTE[..8]);
        assert!(error.contains("missing the manager endpoint"), "{error}");
        assert_eq!(refusal(&["--cert", "cert.pem"]), "missing flag --key");
    }

    #[test]
    fn configuration_path_mixed_with_flags_is_refused() {
        let error = refusal(&["--cert", "cert.pem", "config.toml"]);
        assert!(error.contains("not a manager endpoint"), "{error}");
        assert!(error.contains("cannot be combined with flags"), "{error}");

        let mut arguments = REMOTE.to_vec();
        arguments[8] = "config.toml";
        let error = refusal(&arguments);
        assert!(error.contains("cannot be combined with flags"), "{error}");

        let mut arguments = REMOTE.to_vec();
        arguments.push("config.toml");
        assert_eq!(refusal(&arguments), "too many arguments");
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_is_created_with_mode_0700() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let state_dir = temp_dir.path().join("parent").join("state");
        let resolved = prepare_state_dir(&state_dir).expect("state directory is created");
        assert_eq!(resolved, state_dir);
        let mode = std::fs::metadata(&state_dir)
            .expect("state directory exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        assert_eq!(
            std::fs::read_dir(&state_dir)
                .expect("state directory is readable")
                .count(),
            0,
            "the write check leaves nothing behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_state_dir_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let state_dir = temp_dir.path().join("state");
        std::fs::create_dir(&state_dir).expect("state directory is created");
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755))
            .expect("permissions are set");
        prepare_state_dir(&state_dir).expect("existing state directory is used");
        let mode = std::fs::metadata(&state_dir)
            .expect("state directory exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn relative_state_dir_is_resolved_against_the_working_directory() {
        let temp_dir = tempfile::tempdir_in(".").expect("temporary directory");
        let name = temp_dir
            .path()
            .file_name()
            .expect("temporary directory has a name");
        let relative = Path::new(name).join("state");
        let resolved = prepare_state_dir(&relative).expect("state directory is created");
        assert_eq!(
            resolved,
            std::env::current_dir()
                .expect("working directory")
                .join(&relative)
        );
        assert!(resolved.is_dir());
    }

    #[test]
    fn state_dir_that_is_a_file_is_refused() {
        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let file = temp_dir.path().join("file");
        std::fs::write(&file, "").expect("file is written");
        let error = prepare_state_dir(&file).expect_err("a file is not a state directory");
        assert!(error.to_string().contains("is not a directory"), "{error}");

        let error =
            prepare_state_dir(&file.join("state")).expect_err("a file cannot hold a directory");
        assert!(
            error
                .to_string()
                .contains("cannot create the state directory"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_state_dir_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let state_dir = temp_dir.path().join("state");
        std::fs::create_dir(&state_dir).expect("state directory is created");
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o500))
            .expect("permissions are set");
        // Root can write to the directory regardless of its mode.
        let writable = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(state_dir.join("probe"))
            .is_ok();
        if !writable {
            let error =
                prepare_state_dir(&state_dir).expect_err("an unwritable directory is refused");
            assert!(error.to_string().contains("is not writable"), "{error}");
        }
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))
            .expect("permissions are restored");
    }
}
