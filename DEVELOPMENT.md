# Development

This document describes aspects of the project relevant to developers of Tinny
itself.

## Versioning

This project contains a number of different parts, and therefore the versioning
can seem complicated. There are 3 distinct versions.

1. The Tinny Cargo package version
2. The Can file schema version
3. The Tinny web user-interface (WUI) version

The Tinny version as it appears in the `Cargo.toml` in Git, GitHub Releases, and
Cargo refers to the Cargo package, which is mainly about the library. The `can`
_binary_ is part of that package and so shares that version. This version follows
[semantic versioning][semver].

The `can.yaml` file schema has it's own version which appears inside the file.
This version is a simple number.

The web user-interface (WUI) is a Node package which is compiled and bundled as
a static website into the `dist` directory. When the Tinny package is built, whatever
is in that directory is included in the package, and embedded at compile time into
the Tinny library crate; thus it has its own [semantic version][semver].

### Automatic Versioning

Tinny's version is calculated at build time from the build environment,
the repository, and the working directory.

#### Cargo Package or Dependency

These two contexts always use the version as written in `Cargo.toml`, with no bump
or pre-release tag. It needs only a Rust/Cargo toolchain.

* **Packaging** — `cargo package`/`cargo publish` (including its own dry-run
  verification build), or building an already-packaged/vendored source tree (e.g.
  `cargo install`, since a downloaded `.crate` has no `.git`). Detected by
  [`.cargo_vcs_info.json`][cargo_vcs_info] being present at the crate root, or more
  generally by there being no `.git` working directory (or no `git` tool) to ask.
* **Consumption as a dependency** — tinny being built as a dependency inside someone
  else's `Cargo.toml`, not as the package they're directly building. Detected by the
  absence of Cargo's [`CARGO_PRIMARY_PACKAGE`][cargo_primary_package] build-script
  environment variable, which Cargo sets only for packages being built directly.

Build metadata may still be attached opportunistically here from `.cargo_vcs_info.json`
(see below) — SemVer build metadata never affects a version's precedence, so attaching
it doesn't alter the version's meaning.

#### Other builds

Every other `cargo build`/`test`/`run` a contributor or CI job runs inside a checkout
of this repository defaults to a **pre-release** version: a bump attempt, a pre-release
tag, and build metadata. The one exception is the **release build**: HEAD is exactly at
a tag matching `CARGO_PKG_VERSION`, and the working tree is clean. That's the state the
GitHub release pipeline leaves the repository in immediately after tagging, which only
happens once every check has passed (see `publish.yml`) — nobody reaches it by accident.
There, and only there, the version is exactly `CARGO_PKG_VERSION`, with no pre-release
tag: the official release version.

If `git` isn't available at all, or there's no Git working directory to inspect, this
whole section is moot and we get the same plain outcome as above.

#### Tools

Two external CLIs are used opportunistically, each detected independently by attempting
to invoke it (a failed spawn or non-zero exit counts as "not available"):

* `git` — read-only repository introspection (HEAD hash, dirty state, commit timestamp,
  tags). Needed for everything in this section, including the plain-build checks above.
* `git-cliff` — computing a conventional-commits version bump. Only consulted once `git`
  has confirmed this isn't a plain or release build.

Both are invoked as subprocesses; automatic versioning works whether or not these
happen to be installed, and the plain-build paths must never need to compile or link
them at all.

#### Build metadata (`+...`)

Tried in this order, independently of everything else in this section:

1. **[`.cargo_vcs_info.json`][cargo_vcs_info]**, if present — its `git.sha1` and
   `git.dirty` fields. This is what makes build metadata available even for a packaging
   build, or for anyone who later `cargo install`s or vendors the published crate, with
   no `.git` directory in sight.
2. Otherwise, if `git` is available and this is a Git working directory: the HEAD
   commit's short hash and whether the tree is dirty (uncommitted or untracked changes),
   read from `git` directly.
3. Otherwise: no build metadata is attached.

When both a commit hash and a CI-native build reference are available (e.g. GitHub
Actions' `GITHUB_RUN_ID`+`GITHUB_RUN_ATTEMPT`), prefer the CI-native reference, to
disambiguate repeated builds of the same commit.

#### Version core and pre-release tag

1. If `git` isn't available, or there's no Git working directory: plain outcome —
   `CARGO_PKG_VERSION`, no pre-release (same as a plain build above; this is also what
   happens if a packaging build somehow reaches this point at all, since it will already
   have been caught above).
2. If HEAD is exactly at a tag matching `CARGO_PKG_VERSION`, and the tree is clean:
   **release build** — `major.minor.patch` = `CARGO_PKG_VERSION`, no pre-release.
3. Otherwise, this is a development build, always pre-release:
   * If `git-cliff` is available, run `git-cliff --bumped-version` to get the next
     semantic version implied by conventional commits since the last tag; this becomes
     `major.minor.patch`.
   * If `git-cliff` isn't available, increment the patch by one and use
     `max(candidate, CARGO_PKG_VERSION)` as `major.minor.patch` (ordinary SemVer
     precedence comparison). This needs only `git` and guarantees the result always
     sorts after the last real release regardless of whether Cargo.toml has been
     manually bumped yet on this branch, while still honouring a manual minor/major
     bump already committed. If no tag is reachable at all, fall back to
     `CARGO_PKG_VERSION` unchanged.
   * **Pre-release identifier**: the HEAD commit's timestamp (commit time if clean,
     build time if dirty, so a dirty rebuild always sorts later than the last clean one),
     formatted so pre-release identifiers still order correctly.

#### Assembly

`{major.minor.patch}` + (`-{prerelease}` if this was a development build) +
(`+{buildmeta}` if any source above produced one).

[semver]: https://semver.org/
[cargo_vcs_info]: https://doc.rust-lang.org/cargo/commands/cargo-package.html#cargo_vcs_infojson-format
[cargo_primary_package]: https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts
