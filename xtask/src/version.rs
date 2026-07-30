#![allow(dead_code)]

#[derive(Clone, Debug)]
pub struct CommitInfo {
    pub oid_short: String,
    pub message: String,
    pub is_breaking: bool,
    pub type_part: String,
    pub desc_part: String,
}

pub struct GitVersionInfo {
    pub last_tag: String,
    pub next_version: String,
    pub bump: String,
    pub is_dirty: bool,
    pub head_oid: git2::Oid,
    pub commit_time_secs: i64,
    pub commits: Vec<CommitInfo>,
}

pub fn get_git_version_info() -> Result<GitVersionInfo, Box<dyn std::error::Error>> {
    use git_cliff_core::commit::Commit as CliffCommit;
    use git_cliff_core::repo::Repository;
    use std::path::PathBuf;

    let repo = Repository::discover(PathBuf::from("."))?;
    let inner_repo = git2::Repository::open(".")?;

    let head_commit = inner_repo.head()?.resolve()?.peel_to_commit()?;
    let head_oid = head_commit.id();

    let is_dirty = inner_repo
        .statuses(Some(git2::StatusOptions::new().include_untracked(true)))
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    // Find the last tag
    let mut last_tag = "0.0.0".to_string();
    let mut last_tag_commit = None;
    if let Ok(tags) = inner_repo.tag_names(None) {
        for tag_name in tags.iter().flatten() {
            if let Ok(obj) = inner_repo.revparse_single(tag_name) {
                if let Ok(peeled) = obj.peel_to_commit() {
                    if let Ok(is_ancestor) = inner_repo.graph_descendant_of(head_oid, peeled.id()) {
                        if is_ancestor || peeled.id() == head_oid {
                            last_tag = tag_name.to_string();
                            last_tag_commit = Some(peeled.id());
                        }
                    }
                }
            }
        }
    }

    let clean_last_tag = last_tag.strip_prefix('v').unwrap_or(&last_tag).to_string();

    // Construct the commit range for git-cliff-core
    let range = match last_tag_commit {
        Some(ltc) if ltc != head_oid => format!("{}..{}", ltc, head_oid),
        _ if last_tag_commit.is_some() => String::new(), // exactly on the tagged commit
        _ => head_oid.to_string(),
    };

    let mut commits_info = Vec::new();
    let mut bump = "none";

    if !range.is_empty() {
        if let Ok(commits) = repo.commits(Some(&range), None, None, false) {
            for commit in commits {
                let cliff_commit = CliffCommit::from(&commit);
                if let Ok(conv_commit) = cliff_commit.into_conventional() {
                    let first_line = conv_commit
                        .message
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if first_line.is_empty() {
                        continue;
                    }

                    let is_breaking = conv_commit
                        .conv
                        .as_ref()
                        .map(|c| c.breaking())
                        .unwrap_or(false)
                        || first_line.contains('!')
                        || conv_commit.message.contains("BREAKING CHANGE:");

                    if is_breaking {
                        bump = "major";
                    }

                    let type_part = conv_commit
                        .conv
                        .as_ref()
                        .map(|c| c.type_().to_string())
                        .unwrap_or_else(|| {
                            let type_str = first_line.splitn(2, ':').next().unwrap_or("").trim();
                            if let Some(idx) = type_str.find('(') {
                                type_str[..idx].trim().to_string()
                            } else {
                                type_str.trim_end_matches('!').trim().to_string()
                            }
                        });

                    let desc_part = conv_commit
                        .conv
                        .as_ref()
                        .map(|c| c.description().to_string())
                        .unwrap_or_else(|| {
                            first_line
                                .splitn(2, ':')
                                .nth(1)
                                .unwrap_or("")
                                .trim()
                                .to_string()
                        });

                    if !is_breaking {
                        if type_part == "feat" {
                            if bump != "major" {
                                bump = "minor";
                            }
                        } else if (type_part == "fix"
                            || type_part == "refactor"
                            || type_part == "perf")
                            && bump == "none"
                        {
                            bump = "patch";
                        }
                    }

                    commits_info.push(CommitInfo {
                        oid_short: conv_commit.id[..7].to_string(),
                        message: conv_commit.message,
                        is_breaking,
                        type_part,
                        desc_part,
                    });
                }
            }
        }
    }

    // Bump the version
    let mut parts: Vec<u32> = clean_last_tag
        .split('.')
        .map(|s| s.parse().unwrap_or(0))
        .collect();
    while parts.len() < 3 {
        parts.push(0);
    }

    if bump != "none" {
        if parts[0] == 0 {
            match bump {
                "major" | "minor" => parts[1] += 1,
                _ => parts[2] += 1,
            }
            if bump == "major" || bump == "minor" {
                parts[2] = 0;
            }
        } else {
            match bump {
                "major" => {
                    parts[0] += 1;
                    parts[1] = 0;
                    parts[2] = 0;
                }
                "minor" => {
                    parts[1] += 1;
                    parts[2] = 0;
                }
                _ => {
                    parts[2] += 1;
                }
            }
        }
    }

    let next_version = format!("{}.{}.{}", parts[0], parts[1], parts[2]);

    Ok(GitVersionInfo {
        last_tag,
        next_version,
        bump: bump.to_string(),
        is_dirty,
        head_oid,
        commit_time_secs: head_commit.time().seconds(),
        commits: commits_info,
    })
}
