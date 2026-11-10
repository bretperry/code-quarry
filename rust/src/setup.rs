//! `quarry setup`: tells the repo's AI agents to use quarry. Writes the same short rule into
//! `AGENTS.md`, which most agents read, and into each agent-specific rules file it finds. Shows the
//! plan and writes nothing until the user agrees.

use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

const RULE: &str = "## Code search

To find where something lives in this repo, run `quarry search \"<plain-English question>\"` before grepping or reading many files. It returns the top 5 functions with `path:lines` and their code, with detected secrets removed. It re-indexes by itself when files change.
";

/// Already present when a file mentions this.
const MARKER: &str = "quarry search";

/// When an agent counts as in use: a path in the repo, or a config folder in the home folder.
enum When {
    Always,
    RepoFile(&'static str),
    RepoDir(&'static str),
    RepoOrHome(&'static [&'static str], &'static str),
}

struct Target {
    /// The file written, relative to the repo.
    file: &'static str,
    /// Text put before the rule in a file of quarry's own. `None` means the rule is added to a
    /// shared file, which may already hold the user's own rules.
    own: Option<&'static str>,
    when: When,
}

const TARGETS: &[Target] = &[
    // Codex, Cursor, Copilot, Amp, Zed, OpenCode, Jules, Windsurf and others read AGENTS.md.
    Target { file: "AGENTS.md", own: None, when: When::Always },
    // Claude Code and Gemini CLI read their own file instead.
    Target { file: "CLAUDE.md", own: None, when: When::RepoOrHome(&["CLAUDE.md", ".claude"], ".claude") },
    Target { file: "GEMINI.md", own: None, when: When::RepoOrHome(&["GEMINI.md", ".gemini"], ".gemini") },
    Target { file: ".github/copilot-instructions.md", own: None, when: When::RepoFile(".github/copilot-instructions.md") },
    Target { file: ".clinerules", own: None, when: When::RepoFile(".clinerules") },
    Target { file: ".clinerules/quarry.md", own: Some(""), when: When::RepoDir(".clinerules") },
    Target {
        file: ".cursor/rules/quarry.mdc",
        own: Some("---\ndescription: Code search with quarry\nalwaysApply: true\n---\n\n"),
        when: When::RepoDir(".cursor/rules"),
    },
    Target { file: ".windsurf/rules/quarry.md", own: Some("---\ntrigger: always_on\n---\n\n"), when: When::RepoDir(".windsurf/rules") },
    Target { file: ".kiro/steering/quarry.md", own: Some("---\ninclusion: always\n---\n\n"), when: When::RepoDir(".kiro/steering") },
    Target { file: ".roo/rules/quarry.md", own: Some(""), when: When::RepoDir(".roo/rules") },
];

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from)
}

fn applies(when: &When, repo: &Path, home: Option<&Path>) -> bool {
    match when {
        When::Always => true,
        When::RepoFile(p) => repo.join(p).is_file(),
        When::RepoDir(p) => repo.join(p).is_dir(),
        When::RepoOrHome(paths, dir) => {
            paths.iter().any(|p| repo.join(p).exists()) || home.is_some_and(|h| h.join(dir).is_dir())
        }
    }
}

/// Each file to write, with its new full text and whether it exists now.
fn plan(repo: &Path, home: Option<&Path>) -> Vec<(&'static str, String, bool)> {
    let mut out = Vec::new();
    for t in TARGETS.iter().filter(|t| applies(&t.when, repo, home)) {
        let existing = fs::read_to_string(repo.join(t.file)).ok();
        if existing.as_deref().is_some_and(|s| s.contains(MARKER)) {
            continue;
        }
        let text = match (&existing, t.own) {
            (Some(old), None) if !old.trim().is_empty() => format!("{}\n\n{RULE}", old.trim_end()),
            (_, own) => format!("{}{RULE}", own.unwrap_or("")),
        };
        out.push((t.file, text, existing.is_some()));
    }
    out
}

fn confirmed() -> bool {
    eprint!("Apply? [y/N] ");
    let _ = io::stderr().flush();
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer).is_ok() && matches!(answer.trim(), "y" | "Y" | "yes" | "Yes")
}

pub fn run(folder: PathBuf, yes: bool) -> Result<(), String> {
    let folder = folder.canonicalize().map_err(|e| format!("no such folder: {}: {e}", folder.display()))?;
    let repo = crate::search::git_root(&folder).unwrap_or(folder);
    let changes = plan(&repo, home().as_deref());

    if changes.is_empty() {
        crate::emit(&format!("{}: agent rules already mention quarry.\n", repo.display()));
    } else {
        let mut text = format!("quarry setup, in {}:\n", repo.display());
        for (file, _, exists) in &changes {
            text += &format!("  {} {file}\n", if *exists { "add the quarry rule to" } else { "create" });
        }
        text += "  build the index\n\nThe rule it adds:\n\n";
        text += &RULE.lines().map(|l| if l.is_empty() { "\n".to_string() } else { format!("  {l}\n") }).collect::<String>();
        crate::emit(&text);
        if !yes {
            if !io::stdin().is_terminal() {
                crate::emit("\nNothing written. Run `quarry setup --yes` to apply.\n");
                return Ok(());
            }
            if !confirmed() {
                crate::emit("Nothing written.\n");
                return Ok(());
            }
        }
        for (file, text, _) in &changes {
            let path = repo.join(file);
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
            }
            fs::write(&path, text).map_err(|e| format!("writing {}: {e}", path.display()))?;
        }
    }
    crate::emit(&crate::index::build(&repo)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("quarry-setup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_bare_repo_gets_only_agents_md() {
        let repo = temp("bare");
        let files: Vec<_> = plan(&repo, None).into_iter().map(|(f, _, _)| f).collect();
        assert_eq!(files, ["AGENTS.md"]);
    }

    #[test]
    fn existing_rules_are_kept_and_the_rule_is_added_once() {
        let repo = temp("keep");
        fs::write(repo.join("CLAUDE.md"), "# Mine\n\nBe nice.\n").unwrap();
        let changes = plan(&repo, None);
        let (_, text, exists) = changes.iter().find(|(f, _, _)| *f == "CLAUDE.md").unwrap();
        assert!(*exists);
        assert!(text.starts_with("# Mine\n\nBe nice.\n\n## Code search\n"), "{text}");
        fs::write(repo.join("CLAUDE.md"), text).unwrap();
        assert!(plan(&repo, None).iter().all(|(f, _, _)| *f != "CLAUDE.md"));
    }

    #[test]
    fn agents_are_found_by_their_folders() {
        let repo = temp("folders");
        let home = temp("home");
        fs::create_dir_all(home.join(".gemini")).unwrap();
        fs::create_dir_all(repo.join(".cursor/rules")).unwrap();
        fs::create_dir_all(repo.join(".clinerules")).unwrap();
        let files: Vec<_> = plan(&repo, Some(&home)).into_iter().map(|(f, _, _)| f).collect();
        assert_eq!(files, ["AGENTS.md", "GEMINI.md", ".clinerules/quarry.md", ".cursor/rules/quarry.mdc"]);
        let cursor = plan(&repo, Some(&home)).into_iter().find(|(f, _, _)| f.ends_with(".mdc")).unwrap().1;
        assert!(cursor.starts_with("---\n") && cursor.contains("alwaysApply: true"));
    }
}
