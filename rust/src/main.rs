mod chunk;
mod embed;
mod index;
mod redact;
mod search;
mod store;
mod terms;

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
code-scry: plain-English code search. Secrets are stripped by detection; see README for limits.

  code-scry index [folder]                       build .code-scry/index (default: .)
  code-scry search <question...> [options]       print the best functions with their code
      -k <n>         results (default 5)
      --lines <n>    code lines per result (default: the whole function, capped)
      --repo <dir>   folder to search from (default: current folder)
";

/// Writes to stdout. A reader that stopped early (`| head`) is normal, so that ends the run with
/// success; `println!` would panic there.
pub fn emit(text: &str) {
    let mut out = io::stdout().lock();
    if let Err(e) = out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        if e.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("code-scry: writing output: {e}");
        std::process::exit(1);
    }
}

fn number(v: Option<String>, flag: &str) -> Result<usize, String> {
    v.and_then(|s| s.parse().ok()).ok_or_else(|| format!("{flag} needs a number"))
}

fn dispatch(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    match args.next().as_deref() {
        Some("index") => {
            let repo = args.next().unwrap_or_else(|| ".".into());
            index::run(PathBuf::from(repo))
        }
        Some("search") => {
            let (mut words, mut repo, mut k, mut lines) = (Vec::new(), None, 5, None);
            while let Some(a) = args.next() {
                match a.as_str() {
                    "-k" => k = number(args.next(), "-k")?,
                    "--lines" => lines = Some(number(args.next(), "--lines")?),
                    "--repo" => repo = Some(PathBuf::from(args.next().ok_or("--repo needs a folder")?)),
                    _ => words.push(a),
                }
            }
            if words.is_empty() {
                return Err(USAGE.into());
            }
            search::run(words.join(" "), repo, k, lines)
        }
        Some("-h" | "--help" | "help") => {
            emit(USAGE);
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

fn main() -> ExitCode {
    // Rust's default panic message can quote the string being sliced, which might hold a secret.
    std::panic::set_hook(Box::new(|_| eprintln!("code-scry: internal error")));
    match dispatch(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
