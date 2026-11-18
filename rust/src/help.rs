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
  grep <pattern>      find exact text, with secrets cut out
  setup [folder]      add the quarry rule to your agents' rules files
  index [folder]      build the index by hand (search does it for you in git)
  sensitive-list      print the files that should never be read raw
  env-keys <file>     print the key names in a .env file, never the values
  help [command]      more on one command: quarry help search
  version             print the version

Tips
  Ask the way you'd ask a teammate: \"where do we check the password\".
  Use the code's own words when you know them. They count the most.
  Not in the top 5? Rephrase once, then try quarry grep.

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

pub const GREP: &str = "quarry grep [options] <pattern> [path...]

Finds lines that match the pattern, like grep, in the text quarry shows:
secrets are cut out first, so they never reach your screen or your agent.
Prints path:line:text. Needs no index. Run it anywhere.

The pattern is a Rust regex (no -P, no backreferences or lookaround).
Paths are inside the folder being searched; none means the whole folder.

Options
  -F              the pattern is plain text, not a regex
  -i              ignore case
  -w              match whole words only
  -A/-B/-C <n>    lines of context after, before, or around each match
  -l              print only the paths that match
  -c              print path:count for each path that matches
  -m <n>          stop after n matching lines in each file
  -n              accepted; line numbers are always shown
  -g <glob>       only paths that match; !glob leaves them out. Repeatable.
                  A glob without / matches any part of a path (*.ts, dist).
  --no-ignore     also search git-ignored files
  --repo <dir>    search this folder instead of the current one

Exit codes: 0 a match, 1 no match, 2 an error.

In a git repo it searches the tracked and unignored files. Elsewhere it
walks the folder and skips folders that start with a dot. Files over 500 KB,
binary files, and symlinks are skipped. Sensitive files are withheld and
named on stderr, as is a count of files that had redactions: a match inside
a redacted part can't show.

Output is cut at 20,000 characters, and lines at 300.

Examples
  quarry grep -n \"TODO\" src/
  quarry grep -F -i \"process.env\" -g \"*.ts\" -g \"!*.test.ts\"
  quarry grep -l -w retry
";

pub const SENSITIVE_LIST: &str = "quarry sensitive-list --json

Prints the files that should never be read raw, as one line of JSON:
  {\"dirs\":[..],\"names\":[..],\"extensions\":[..],\"exempt_suffixes\":[..]}

  dirs              a folder with this name anywhere in the path
  names             a file name; a trailing * means \"starts with\"
  extensions        a file extension, without the dot
  exempt_suffixes   a name ending this way is a template, not on the list

Names and extensions ignore case. This is the short list agents' guards
refuse to open. quarry itself skips more files than these.
";

pub const ENV_KEYS: &str = "quarry env-keys <file>

Prints the key names in a .env-style file, one per line, in order. Never
a value, never an =. Comments, blank lines, and the lines inside a
multi-line value are skipped. A key file (PEM) is refused.

Example
  quarry env-keys .env
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
        "grep" => Some(GREP),
        "sensitive-list" => Some(SENSITIVE_LIST),
        "env-keys" => Some(ENV_KEYS),
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
        for text in [MAIN, SEARCH, GREP, SENSITIVE_LIST, ENV_KEYS, SETUP, INDEX] {
            for line in text.lines() {
                assert!(line.chars().count() <= 80, "{line}");
            }
        }
    }
}
