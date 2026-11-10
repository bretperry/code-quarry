//! Help text. Kept under 80 columns so it reads in any terminal.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const MAIN: &str = concat!(
    "quarry ",
    env!("CARGO_PKG_VERSION"),
    "
Ask your codebase a question. Get back the functions that answer it.

Quick start
  quarry setup                       tell your AI agents about quarry
  quarry search \"where do we retry failed requests\"

Commands
  search <question>   print the best-matching functions, with their code
  setup [folder]      add the quarry rule to your agents' rules files
  index [folder]      build the index by hand (search does it for you in git)
  help [command]      more on one command: quarry help search
  version             print the version

Tips
  Ask the way you'd ask a teammate: \"where do we check the password\".
  Use the code's own words when you know them. They count the most.
  Not in the top 5? Rephrase once, then try grep.

Secrets are cut from everything quarry stores and prints.
More: https://github.com/bretperry/code-quarry
"
);

pub const SEARCH: &str = "quarry search <question> [options]

Prints the functions that best answer the question, best first, each with
its code. Run it anywhere inside the repo.

Options
  -k <n>          how many results (default 5)
  --lines <n>     code lines per result (default: the whole function, capped)
  --repo <dir>    search this folder instead of the current one
  --no-refresh    don't re-index first, even if files changed

Each result starts with a header line, then the code:
  --- 0.917 scripts/lock.mjs:212-218 stale (function)
      score path:first-last name (kind)

The score runs from 0 to 1; 1 is a perfect match. Secrets in the code
show as [REDACTED].

In a git repo, search builds the index the first time and rebuilds it when
a file changed (about a second). Only git-tracked files are searched.

Examples
  quarry search \"where do we parse dates\"
  quarry search \"auth middleware\" -k 10 --lines 20
  quarry search \"retry logic\" --repo ~/Dev/api
";

pub const SETUP: &str = "quarry setup [folder] [--yes]

Tells the AI agents in this repo to use quarry, then builds the index.
Shows what it will change and asks first. --yes skips the question.

It adds one short rule to:
  AGENTS.md                         always (Codex, Cursor, Copilot, Amp,
                                    Zed, OpenCode, Jules and others)
  CLAUDE.md, GEMINI.md              when Claude Code or Gemini CLI is in use
  .github/copilot-instructions.md   when it exists
  .cursor/rules/  .windsurf/rules/  .clinerules  .kiro/steering/  .roo/rules/
                                    when the folder exists

Your own rules stay as they are. Running setup again changes nothing.
";

pub const INDEX: &str = "quarry index [folder]

Builds .quarry/index for the folder (default: the current one). It holds
no source text, and git ignores it by itself.

You rarely need this: in a git repo, search builds and refreshes the index.
Outside git, run it once, and again after big changes.

Only git-tracked files are indexed. Outside git, every file is, except
folders like node_modules, target and dist. Files that look sensitive
(.env, keys, anything named secret or password) are always skipped.
";

/// Help for one command, by name.
pub fn for_command(name: &str) -> Option<&'static str> {
    match name {
        "search" => Some(SEARCH),
        "setup" => Some(SETUP),
        "index" => Some(INDEX),
        "help" | "version" => Some(MAIN),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_fits_in_80_columns() {
        for text in [MAIN, SEARCH, SETUP, INDEX] {
            for line in text.lines() {
                assert!(line.chars().count() <= 80, "{line}");
            }
        }
    }
}
