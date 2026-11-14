//! Explicit per-app exclusion list, modelled after Zygisk Next.
//!
//! Two modes are supported, selected through
//! `/data/adb/modules/admirepowered/denylist_mode`:
//!
//! * `just_umount` (default): the process is excluded from mount hiding, but
//!   Zygisk modules are still injected and hooked.
//! * `enforce`: the process is excluded entirely, no module is loaded at all.
//!
//! Excluded packages are read from
//! `/data/adb/modules/admirepowered/denylist_apps`, one package per line.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;

use crate::constants::{PATH_DENYLIST_APPS, PATH_DENYLIST_MODE};

/// Android allocates one 100000-wide UID range per user.
const PER_USER_RANGE: i32 = 100_000;
/// Regular application UIDs (`AID_APP_START..=AID_APP_END`), so excluding an app
/// can never accidentally affect system_server or any system UID.
const AID_APP_START: i32 = 10_000;
const AID_APP_END: i32 = 19_999;
const PACKAGES_LIST: &str = "/data/system/packages.list";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Mode {
    #[default]
    JustUmount,
    Enforce,
}

impl Mode {
    fn parse(value: &str) -> Mode {
        match value.trim() {
            "enforce" => Mode::Enforce,
            _ => Mode::JustUmount,
        }
    }
}

/// Cheap change detector for a config file, so the daemon does not re-read and
/// re-parse the exclusion list for every app process.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
struct Stamp {
    exists: bool,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
}

fn stamp(path: &str) -> Stamp {
    match fs::metadata(path) {
        Ok(meta) => Stamp {
            exists: true,
            len: meta.len(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        },
        Err(_) => Stamp::default(),
    }
}

struct Config {
    mode: Mode,
    /// App IDs (first 100000-wide bucket) resolved from `packages.list`.
    app_ids: HashSet<i32>,
    mode_stamp: Stamp,
    apps_stamp: Stamp,
    packages_stamp: Stamp,
}

static CONFIG: Mutex<Option<Config>> = Mutex::new(None);

fn read_package_names() -> HashSet<String> {
    let content = match fs::read_to_string(PATH_DENYLIST_APPS) {
        Ok(content) => content,
        Err(_) => return HashSet::new(),
    };
    content
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Resolve package names to app IDs using the system package database.
///
/// Several packages may share one UID (sharedUserId). Such an app ID is only
/// excluded when *every* package mapping to it is listed, so that excluding one
/// app can never silently strip modules from an unrelated one.
fn resolve_app_ids(packages: &HashSet<String>) -> HashSet<i32> {
    let mut app_ids = HashSet::new();
    let content = match fs::read_to_string(PACKAGES_LIST) {
        Ok(content) => content,
        Err(_) => return app_ids,
    };
    // app id -> (total packages, excluded packages)
    let mut by_app_id: HashMap<i32, (usize, usize)> = HashMap::new();
    for line in content.lines() {
        // Format: <name> <uid> [<debuggable> <dataDir> ...]
        let mut fields = line.split_whitespace();
        let (Some(name), Some(uid)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Ok(uid) = uid.parse::<i32>() else {
            continue;
        };
        let app_id = uid.rem_euclid(PER_USER_RANGE);
        if !(AID_APP_START..=AID_APP_END).contains(&app_id) {
            continue;
        }
        let entry = by_app_id.entry(app_id).or_insert((0, 0));
        entry.0 += 1;
        if packages.contains(name) {
            entry.1 += 1;
        }
    }
    for (app_id, (total, excluded)) in by_app_id {
        if excluded > 0 && total == excluded {
            app_ids.insert(app_id);
        }
    }
    app_ids
}

fn reload(mode_stamp: Stamp, apps_stamp: Stamp, packages_stamp: Stamp) -> Config {
    let mode = fs::read_to_string(PATH_DENYLIST_MODE)
        .map(|value| Mode::parse(&value))
        .unwrap_or_default();
    let packages = read_package_names();
    let app_ids = if packages.is_empty() {
        HashSet::new()
    } else {
        resolve_app_ids(&packages)
    };
    Config {
        mode,
        app_ids,
        mode_stamp,
        apps_stamp,
        packages_stamp,
    }
}

/// Return the current exclusion mode and whether `uid` is explicitly excluded.
pub fn query(uid: i32) -> (Mode, bool) {
    let mode_stamp = stamp(PATH_DENYLIST_MODE);
    let apps_stamp = stamp(PATH_DENYLIST_APPS);
    let packages_stamp = stamp(PACKAGES_LIST);

    let mut guard = CONFIG.lock().unwrap_or_else(|err| err.into_inner());
    let stale = match guard.as_ref() {
        None => true,
        Some(config) => {
            config.mode_stamp != mode_stamp
                || config.apps_stamp != apps_stamp
                || config.packages_stamp != packages_stamp
        }
    };
    if stale {
        *guard = Some(reload(mode_stamp, apps_stamp, packages_stamp));
    }
    let config = guard.as_ref().unwrap();
    let app_id = uid.rem_euclid(PER_USER_RANGE);
    (config.mode, config.app_ids.contains(&app_id))
}
