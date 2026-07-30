#[cfg(feature = "version-from-git")]
#[path = "xtask/src/version.rs"]
mod version;

#[cfg(feature = "version-from-git")]
fn calculate_version() -> String {
    use chrono::{TimeZone, Utc};
    use version::get_git_version_info;

    let info = match get_git_version_info() {
        Ok(i) => i,
        Err(_) => return env!("CARGO_PKG_VERSION").to_string(),
    };

    // Determine timestamp (hybrid: build time if dirty, commit time if clean)
    let timestamp_str = if info.is_dirty {
        Utc::now().format("%Y%m%d%H%M%S").to_string()
    } else if let Some(dt) = Utc.timestamp_opt(info.commit_time_secs, 0).single() {
        dt.format("%Y%m%d%H%M%S").to_string()
    } else {
        Utc::now().format("%Y%m%d%H%M%S").to_string()
    };

    let short_sha = &info.head_oid.to_string()[..7];
    let dirty_suffix = if info.is_dirty { ".dirty" } else { "" };
    format!(
        "{}-{}++{}{}",
        info.next_version, timestamp_str, short_sha, dirty_suffix
    )
}

#[cfg(not(feature = "version-from-git"))]
fn calculate_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=xtask/src/version.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    println!("cargo:rerun-if-changed=.git/refs/tags");

    let version = calculate_version();
    let clean_version = version.replace("++", "+");
    println!("cargo:rustc-env=CARGO_PKG_VERSION={}", clean_version);
}
