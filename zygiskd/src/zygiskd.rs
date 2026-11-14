use crate::constants::{DaemonSocketAction, ProcessFlags};
use crate::utils::{check_unix_socket, LateInit, UnixStreamExt};
use crate::{constants, exclude, lp_select, root_impl, utils};
use anyhow::{bail, Result};
use log::{debug, error, info, trace, warn};
use passfd::FdPassingExt;
use rustix::io::{fcntl_setfd, FdFlags};
use std::collections::HashMap;
use std::fs;
use std::io::{Error, Read};
use std::ops::Deref;
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::os::unix::{
    net::{UnixListener, UnixStream},
    prelude::AsRawFd,
};
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use std::sync::{Arc, Mutex};
use std::thread;

struct Module {
    name: String,
    lib_fd: OwnedFd,
    companion: Mutex<Option<Option<UnixStream>>>,
}

struct Context {
    modules: Vec<Module>,
    /// Live ZN companion processes, keyed by the module library path that was
    /// handed to the injected process.
    zn_companions: Mutex<HashMap<PathBuf, UnixStream>>,
    /// Per-library injection counters reported by injected processes.
    zn_states: Mutex<HashMap<PathBuf, (u32, u32)>>,
}

static TMP_PATH: LateInit<String> = LateInit::new();
static CONTROLLER_SOCKET: LateInit<String> = LateInit::new();
static PATH_CP_NAME: LateInit<String> = LateInit::new();

pub fn main() -> Result<()> {
    info!("Welcome to Zygisk_mod ({}) !", constants::ZKSU_VERSION);

    TMP_PATH.init(std::env::var("TMP_PATH")?);
    CONTROLLER_SOCKET.init(format!("{}/.m", TMP_PATH.deref()));
    PATH_CP_NAME.init(format!(
        "{}/{}",
        TMP_PATH.deref(),
        lp_select!("/.c32", "/.c64")
    ));

    let arch = get_arch()?;
    debug!("Daemon architecture: {arch}");
    let modules = load_modules(arch)?;

    {
        let mut msg = Vec::<u8>::new();
        let info = match root_impl::get_impl() {
            root_impl::RootImpl::KernelSU | root_impl::RootImpl::Magisk | root_impl::RootImpl::Apatch => {
                msg.extend_from_slice(&constants::DAEMON_SET_INFO.to_le_bytes());
                let module_names: Vec<_> = modules.iter().map(|m| m.name.as_str()).collect();
                format!(
                    "Root: {:?},module({}): {}",
                    root_impl::get_impl(),
                    modules.len(),
                    module_names.join(",")
                )
            }
            _ => {
                msg.extend_from_slice(&constants::DAEMON_SET_ERROR_INFO.to_le_bytes());
                format!("Invalid root implementation: {:?}", root_impl::get_impl())
            }
        };
        msg.extend_from_slice(&(info.len() as u32 + 1).to_le_bytes());
        msg.extend_from_slice(info.as_bytes());
        msg.extend_from_slice(&[0u8]);
        utils::unix_datagram_sendto(&CONTROLLER_SOCKET, msg.as_slice())
            .expect("failed to send info");
    }

    let context = Context {
        modules,
        zn_companions: Mutex::new(HashMap::new()),
        zn_states: Mutex::new(HashMap::new()),
    };
    let context = Arc::new(context);
    let listener = create_daemon_socket()?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let context = Arc::clone(&context);
        let action = stream.read_u8()?;
        let action = DaemonSocketAction::try_from(action)?;
        trace!("New daemon action {:?}", action);
        match action {
            DaemonSocketAction::PingHeartbeat => {
                let value = constants::ZYGOTE_INJECTED;
                utils::unix_datagram_sendto(&CONTROLLER_SOCKET, &value.to_le_bytes())?;
            }
            DaemonSocketAction::ZygoteRestart => {
                info!("Zygote restarted, clean up companions");
                for module in &context.modules {
                    let mut companion = module.companion.lock().unwrap();
                    companion.take();
                }
                context.zn_companions.lock().unwrap().clear();
                context.zn_states.lock().unwrap().clear();
            }
            DaemonSocketAction::SystemServerStarted => {
                let value = constants::SYSTEM_SERVER_STARTED;
                utils::unix_datagram_sendto(&CONTROLLER_SOCKET, &value.to_le_bytes())?;
            }
            _ => {
                thread::spawn(move || {
                    if let Err(e) = handle_daemon_action(action, stream, &context) {
                        warn!("Error handling daemon action: {}\n{}", e, e.backtrace());
                    }
                });
            }
        }
    }

    Ok(())
}

fn get_arch() -> Result<&'static str> {
    let system_arch = utils::get_property("ro.product.cpu.abi")?;
    // This module only injects into the 64-bit zygote.
    if system_arch.contains("arm64") {
        return Ok("arm64-v8a");
    }
    bail!(
        "Unsupported system architecture: {} (only arm64-v8a is supported)",
        system_arch
    );
}

fn load_modules(arch: &str) -> Result<Vec<Module>> {
    let mut modules = Vec::new();
    let dir = match fs::read_dir(constants::PATH_MODULES_DIR) {
        Ok(dir) => dir,
        Err(e) => {
            warn!("Failed reading modules directory: {}", e);
            return Ok(modules);
        }
    };
    for entry in dir.into_iter() {
        let entry = entry?;
        let name = entry.file_name().into_string().unwrap();
        let so_path = entry.path().join(format!("zygisk/{arch}.so"));
        let disabled = entry.path().join("disable");
        if !so_path.exists() || disabled.exists() {
            continue;
        }
        info!("  Loading module `{name}`...");
        let lib_fd = match create_library_fd(&so_path) {
            Ok(fd) => fd,
            Err(e) => {
                warn!("  Failed to create memfd for `{name}`: {e}");
                continue;
            }
        };
        let companion = Mutex::new(None);
        let module = Module {
            name,
            lib_fd,
            companion,
        };
        modules.push(module);
    }

    Ok(modules)
}

fn random_memfd_name() -> String {
    // A stable name such as "jit-cache" becomes a reliable fingerprint in
    // /proc/<pid>/maps. Randomize it per module load instead.
    let mut bytes = [0u8; 8];
    let mut randomized = false;
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        randomized = f.read_exact(&mut bytes).is_ok();
    }
    if !randomized || bytes == [0u8; 8] {
        // Never fall back to a constant name: mix in the clock and pid so
        // consecutive loads still differ.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        bytes = (nanos ^ ((std::process::id() as u64) << 32)).to_le_bytes();
    }
    let mut name = String::with_capacity(20);
    name.push_str("jit-");
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(name, "{b:02x}");
    }
    name
}

fn create_library_fd(so_path: &PathBuf) -> Result<OwnedFd> {
    let opts = memfd::MemfdOptions::default().allow_sealing(true);
    let memfd = opts.create(random_memfd_name())?;
    let file = fs::File::open(so_path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut writer = memfd.as_file();
    std::io::copy(&mut reader, &mut writer)?;

    let mut seals = memfd::SealsHashSet::new();
    seals.insert(memfd::FileSeal::SealShrink);
    seals.insert(memfd::FileSeal::SealGrow);
    seals.insert(memfd::FileSeal::SealWrite);
    seals.insert(memfd::FileSeal::SealSeal);
    memfd.add_seals(&seals)?;

    Ok(OwnedFd::from(memfd.into_file()))
}

fn create_daemon_socket() -> Result<UnixListener> {
    utils::set_socket_create_context("u:r:zygote:s0")?;
    let listener = utils::unix_listener_from_path(&PATH_CP_NAME)?;
    Ok(listener)
}

fn spawn_companion(name: &str, lib_fd: RawFd) -> Result<Option<UnixStream>> {
    let (mut daemon, companion) = UnixStream::pair()?;

    // FIXME: avoid getting self path from arg0
    let process = std::env::args().next().unwrap();
    let nice_name = process.split('/').last().unwrap();

    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            bail!(Error::last_os_error());
        } else if pid > 0 {
            drop(companion);
            let mut status: libc::c_int = 0;
            libc::waitpid(pid, &mut status, 0);
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                daemon.write_string(name)?;
                daemon.send_fd(lib_fd)?;
                return match daemon.read_u8()? {
                    0 => Ok(None),
                    1 => Ok(Some(daemon)),
                    _ => bail!("Invalid companion response"),
                };
            } else {
                bail!("exited with status {}", status);
            }
        } else {
            // Remove FD_CLOEXEC flag
            fcntl_setfd(companion.as_fd(), FdFlags::empty())?;
        }
    }

    Command::new(&process)
        .arg0(format!("{}-{}", nice_name, name))
        .arg("companion")
        .arg(format!("{}", companion.as_raw_fd()))
        .spawn()?;
    exit(0)
}

fn handle_daemon_action(
    action: DaemonSocketAction,
    mut stream: UnixStream,
    context: &Context,
) -> Result<()> {
    match action {
        DaemonSocketAction::RequestLogcatFd => loop {
            let level = match stream.read_u8() {
                Ok(level) => level,
                Err(_) => break,
            };
            let tag = stream.read_string()?;
            let message = stream.read_string()?;
            utils::log_raw(level as i32, &tag, &message)?;
        },
        DaemonSocketAction::GetProcessFlags => {
            let uid = stream.read_u32()? as i32;
            let mut flags = ProcessFlags::empty();
            if root_impl::uid_is_manager(uid) {
                flags |= ProcessFlags::PROCESS_IS_MANAGER;
            } else {
                if root_impl::uid_granted_root(uid) {
                    flags |= ProcessFlags::PROCESS_GRANTED_ROOT;
                }
                let (mode, excluded) = exclude::query(uid);
                if excluded || root_impl::uid_should_umount(uid) {
                    flags |= ProcessFlags::PROCESS_ON_DENYLIST;
                    match mode {
                        exclude::Mode::Enforce => {
                            flags |= ProcessFlags::PROCESS_DENYLIST_ENFORCE;
                        }
                        exclude::Mode::JustUmount => {
                            if std::path::Path::new(constants::PATH_CONTROL_DISABLE_UNMOUNT)
                                .exists()
                            {
                                flags |= ProcessFlags::PROCESS_DISABLE_UNMOUNT;
                            }
                        }
                    }
                }
            }
            match root_impl::get_impl() {
                root_impl::RootImpl::KernelSU => flags |= ProcessFlags::PROCESS_ROOT_IS_KSU,
                root_impl::RootImpl::Magisk => flags |= ProcessFlags::PROCESS_ROOT_IS_MAGISK,
                root_impl::RootImpl::Apatch => flags |= ProcessFlags::PROCESS_ROOT_IS_APATCH,
                _ => panic!("wrong root impl: {:?}", root_impl::get_impl()),
            }
            trace!(
                "Uid {} granted root: {}",
                uid,
                flags.contains(ProcessFlags::PROCESS_GRANTED_ROOT)
            );
            trace!(
                "Uid {} on denylist: {}",
                uid,
                flags.contains(ProcessFlags::PROCESS_ON_DENYLIST)
            );
            stream.write_u32(flags.bits())?;
        }
        DaemonSocketAction::ReadModules => {
            stream.write_usize(context.modules.len())?;
            for module in context.modules.iter() {
                stream.write_string(&module.name)?;
                stream.send_fd(module.lib_fd.as_raw_fd())?;
            }
        }
        DaemonSocketAction::RequestCompanionSocket => {
            let index = stream.read_usize()?;
            let module = &context.modules[index];
            let mut companion = module.companion.lock().unwrap();
            if let Some(Some(sock)) = companion.as_ref() {
                if !check_unix_socket(sock, false) {
                    error!("Poll companion for module `{}` crashed", module.name);
                    companion.take();
                }
            }
            if companion.is_none() {
                match spawn_companion(&module.name, module.lib_fd.as_raw_fd()) {
                    Ok(c) => {
                        if c.is_some() {
                            trace!("  Spawned companion for `{}`", module.name);
                        } else {
                            trace!(
                                "  No companion spawned for `{}` because it has not entry",
                                module.name
                            );
                        }
                        *companion = Some(c);
                    }
                    Err(e) => {
                        warn!("  Failed to spawn companion for `{}`: {}", module.name, e);
                    }
                };
            }
            match companion.as_ref() {
                Some(Some(sock)) => {
                    if let Err(e) = sock.send_fd(stream.as_raw_fd()) {
                        error!(
                            "Failed to send companion fd socket of module `{}`: {}",
                            module.name, e
                        );
                        stream.write_u8(0)?;
                    }
                    // Ok: Send by companion
                }
                _ => {
                    stream.write_u8(0)?;
                }
            }
        }
        DaemonSocketAction::GetModuleDir => {
            let index = stream.read_usize()?;
            let module = &context.modules[index];
            let dir = format!("{}/{}", constants::PATH_MODULES_DIR, module.name);
            let dir = fs::File::open(dir)?;
            stream.send_fd(dir.as_raw_fd())?;
        }
        DaemonSocketAction::GetZnPlan => handle_get_zn_plan(&mut stream)?,
        DaemonSocketAction::ReportZnModule => handle_report_zn_module(&mut stream, context)?,
        DaemonSocketAction::RequestZnCompanionSocket => {
            handle_request_zn_companion_socket(&mut stream, context)?
        }
        _ => {}
    }
    Ok(())
}

struct ZnPlanModule {
    lib_path: String,
    companion: bool,
    lib_fd: OwnedFd,
}

/// Only 64-bit AArch64 shared objects are supported. The injected process is
/// always 64-bit, so a 32-bit or foreign-arch library would fail to load.
fn is_elf_matching_arch(path: &Path) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut header = [0u8; 20];
    if file.read_exact(&mut header).is_err() {
        return false;
    }
    if &header[..4] != b"\x7FELF" {
        return false;
    }
    // EI_CLASS == ELFCLASS64
    if header[4] != 2 {
        return false;
    }
    // e_machine == EM_AARCH64 (0xB7), stored little-endian in e_ident[EI_DATA].
    u16::from_le_bytes([header[18], header[19]]) == 0xB7
}

/// Scans every enabled module's `zn_modules.txt` and returns the libraries
/// that should be injected into the current process.
///
/// Only zygote/app_process targets are supported: entries selected by an app
/// package name or an arbitrary process path are skipped.
fn scan_zn_modules_for_target(
    process_name: &str,
    process_path: &str,
) -> Result<Vec<ZnPlanModule>> {
    let mut results = Vec::new();
    let dir = match fs::read_dir(constants::PATH_MODULES_DIR) {
        Ok(d) => d,
        Err(e) => {
            warn!("Failed to read modules directory for ZN: {}", e);
            return Ok(results);
        }
    };

    let mut seen_libs = std::collections::HashSet::new();

    for entry in dir.flatten() {
        let mod_dir = entry.path();
        if mod_dir.join("disable").exists() || mod_dir.join("remove").exists() {
            continue;
        }
        let zn_file = mod_dir.join("zn_modules.txt");
        if !zn_file.exists() {
            continue;
        }

        let content = match fs::read_to_string(&zn_file) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read {}: {}", zn_file.display(), e);
                continue;
            }
        };

        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 2 {
                continue;
            }

            let first = tokens[0];
            let target_matches = if let Some(target_name) = first.strip_prefix("name=") {
                match target_name {
                    "zygote" | "zygote64" => {
                        process_name.contains("zygote") || process_name.contains("app_process")
                    }
                    // The module only injects into the 64-bit zygote.
                    "zygote32" => false,
                    _ => process_name == target_name,
                }
            } else if let Some(target_path) = first.strip_prefix("path=") {
                process_path == target_path
            } else {
                false
            };

            if !target_matches {
                continue;
            }

            let companion = tokens[1..tokens.len() - 1].contains(&"companion");
            let lib_subpath = tokens.last().unwrap();

            let candidate = if lib_subpath.starts_with('/') {
                PathBuf::from(lib_subpath)
            } else {
                mod_dir.join(lib_subpath)
            };

            let canonical_mod = match fs::canonicalize(&mod_dir) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let canonical_lib = match fs::canonicalize(&candidate) {
                Ok(p) => p,
                Err(_) => continue,
            };

            if !canonical_lib.starts_with(&canonical_mod) || canonical_lib == canonical_mod {
                warn!(
                    "ZN module lib `{}` is outside module dir `{}`",
                    canonical_lib.display(),
                    canonical_mod.display()
                );
                continue;
            }

            if !is_elf_matching_arch(&canonical_lib) {
                trace!(
                    "Skipping ZN module lib `{}`: architecture mismatch",
                    canonical_lib.display()
                );
                continue;
            }

            let lib_path_str = canonical_lib.to_string_lossy().into_owned();
            if seen_libs.contains(&lib_path_str) {
                continue;
            }

            match create_library_fd(&canonical_lib) {
                Ok(lib_fd) => {
                    info!(
                        "ZN: prepared module `{}` for {} (companion={})",
                        lib_path_str, process_name, companion
                    );
                    seen_libs.insert(lib_path_str.clone());
                    results.push(ZnPlanModule {
                        lib_path: lib_path_str,
                        companion,
                        lib_fd,
                    });
                }
                Err(e) => {
                    warn!(
                        "Failed to create memfd for ZN module `{}`: {}",
                        lib_path_str, e
                    );
                }
            }
        }
    }

    Ok(results)
}

fn handle_get_zn_plan(stream: &mut UnixStream) -> Result<()> {
    let process_name = stream.read_string()?;
    let process_path = stream.read_string()?;
    debug!(
        "GetZnPlan request for process: name={}, path={}",
        process_name, process_path
    );

    let matching = scan_zn_modules_for_target(&process_name, &process_path)?;
    stream.write_usize(matching.len())?;

    for m in matching {
        stream.write_string(&m.lib_path)?;
        stream.write_u8(if m.companion { 1 } else { 0 })?;
        stream.send_fd(m.lib_fd.as_raw_fd())?;
    }
    Ok(())
}

fn write_zn_state_file(states: &HashMap<PathBuf, (u32, u32)>) {
    let mut lines: Vec<String> = states
        .iter()
        .map(|(path, (injected, failed))| {
            let state = if *failed > 0 {
                "failed"
            } else if *injected > 0 {
                "injected"
            } else {
                "unknown"
            };
            format!("{} {}", state, path.display())
        })
        .collect();
    lines.sort();
    let target = format!("{}/.zs", TMP_PATH.deref());
    let staging = format!("{}.tmp", target);
    let result =
        fs::write(&staging, lines.join("\n") + "\n").and_then(|_| fs::rename(&staging, &target));
    if let Err(e) = result {
        warn!("Failed to write {}: {}", target, e);
    }
}

fn handle_report_zn_module(stream: &mut UnixStream, context: &Context) -> Result<()> {
    let lib_path = PathBuf::from(stream.read_string()?);
    let injected = stream.read_u8()? != 0;

    // Only paths inside the modules directory are tracked; anything else was
    // not handed out by this daemon.
    let modules_dir = match fs::canonicalize(constants::PATH_MODULES_DIR) {
        Ok(p) => p,
        Err(e) => {
            warn!("ZN: cannot canonicalize modules directory: {}", e);
            return Ok(());
        }
    };
    if lib_path.strip_prefix(&modules_dir).is_ok() {
        let mut states = context.zn_states.lock().unwrap();
        let entry = states.entry(lib_path.clone()).or_insert((0, 0));
        if injected {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
        info!(
            "ZN: module `{}` {} (injected={}, failed={})",
            lib_path.display(),
            if injected {
                "injected"
            } else {
                "failed to load"
            },
            entry.0,
            entry.1
        );
        write_zn_state_file(&states);
    } else {
        warn!(
            "ZN: ignoring report for `{}` outside the modules directory",
            lib_path.display()
        );
    }
    Ok(())
}

fn handle_request_zn_companion_socket(
    stream: &mut UnixStream,
    context: &Context,
) -> Result<()> {
    let lib_path = PathBuf::from(stream.read_string()?);

    let mut table = context.zn_companions.lock().unwrap();

    if let Some(sock) = table.get(&lib_path) {
        if !check_unix_socket(sock, false) {
            warn!(
                "ZN companion for `{}` appears to have crashed",
                lib_path.display()
            );
            table.remove(&lib_path);
        }
    }

    if !table.contains_key(&lib_path) {
        match spawn_zn_companion(&lib_path) {
            Ok(Some(sock)) => {
                trace!("Spawned new ZN companion for `{}`", lib_path.display());
                table.insert(lib_path.clone(), sock);
            }
            Ok(None) => {
                warn!(
                    "ZN module `{}` does not have a companion entry point",
                    lib_path.display()
                );
            }
            Err(e) => {
                warn!(
                    "Failed to spawn ZN companion for `{}`: {}",
                    lib_path.display(),
                    e
                );
            }
        }
    }

    match table.get(&lib_path) {
        Some(sock) => {
            if let Err(e) = sock.send_fd(stream.as_raw_fd()) {
                error!(
                    "Failed to send ZN companion FD for `{}`: {}",
                    lib_path.display(),
                    e
                );
                stream.write_u8(0)?;
            }
            // On success the companion notifies the client directly.
        }
        None => {
            stream.write_u8(0)?;
        }
    }
    Ok(())
}

fn spawn_zn_companion(lib_path: &Path) -> Result<Option<UnixStream>> {
    let (mut daemon, companion) = UnixStream::pair()?;

    // FIXME: avoid getting self path from arg0
    let process = std::env::args().next().unwrap();
    let nice_name = process.split('/').last().unwrap();
    let lib_path_str = lib_path.to_string_lossy().into_owned();

    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            bail!(Error::last_os_error());
        } else if pid > 0 {
            drop(companion);
            let mut status: libc::c_int = 0;
            libc::waitpid(pid, &mut status, 0);
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                return match daemon.read_u8()? {
                    0 => Ok(None),
                    1 => Ok(Some(daemon)),
                    _ => bail!("Invalid ZN companion response"),
                };
            } else {
                bail!("exited with status {}", status);
            }
        } else {
            // Remove FD_CLOEXEC flag
            fcntl_setfd(companion.as_fd(), FdFlags::empty())?;
        }
    }

    Command::new(&process)
        .arg0(format!("{}-zn", nice_name))
        .arg("zn-companion")
        .arg(&lib_path_str)
        .arg(format!("{}", companion.as_raw_fd()))
        .spawn()?;
    exit(0)
}
