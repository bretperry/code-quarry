mod chunk;
mod embed;
mod help;
mod index;
mod redact;
mod search;
mod setup;
mod store;
mod terms;

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;


/// Writes to stdout. A reader that stopped early (`| head`) is normal, so that ends the run with
/// success; `println!` would panic there.
pub fn emit(text: &str) {
    let mut out = io::stdout().lock();
    if let Err(e) = out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        if e.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("quarry: writing output: {e}");
        std::process::exit(1);
    }
}

/// A usage mistake: what went wrong, then where to read more.
fn misuse(what: &str, command: &str) -> String {
    format!("quarry: {what}\nRun `quarry help {command}` for how to use it.")
}

fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "-h" || a == "--help")
}

fn dispatch(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let command = args.next();
    let rest: Vec<String> = args.collect();
    if let Some(c) = command.as_deref().filter(|_| wants_help(&rest)) {
        if let Some(text) = help::for_command(c) {
            emit(text);
            return Ok(());
        }
    }
    let mut args = rest.into_iter();
    match command.as_deref() {
        Some("index") => {
            let repo = args.next().unwrap_or_else(|| ".".into());
            if let Some(extra) = args.next() {
                return Err(misuse(&format!("index takes one folder, got also \"{extra}\""), "index"));
            }
            index::run(PathBuf::from(repo))
        }
        Some("search") => {
            let (mut words, mut repo, mut k, mut lines, mut refresh) = (Vec::new(), None, 5, None, true);
            let number = |v: Option<String>, flag: &str| {
                v.and_then(|s| s.parse().ok()).ok_or_else(|| misuse(&format!("{flag} needs a number"), "search"))
            };
            while let Some(a) = args.next() {
                match a.as_str() {
                    "-k" => k = number(args.next(), "-k")?,
                    "--lines" => lines = Some(number(args.next(), "--lines")?),
                    "--no-refresh" => refresh = false,
                    "--repo" => repo = Some(PathBuf::from(args.next().ok_or_else(|| misuse("--repo needs a folder", "search"))?)),
                    _ if a.starts_with("--") => return Err(misuse(&format!("unknown option {a}"), "search")),
                    _ => words.push(a),
                }
            }
            if words.is_empty() {
                return Err(misuse("search needs a question, like: quarry search \"where do we parse dates\"", "search"));
            }
            search::run(words.join(" "), repo, k, lines, refresh)
        }
        Some("setup") => {
            let (mut folder, mut yes) = (None, false);
            for a in args {
                match a.as_str() {
                    "-y" | "--yes" => yes = true,
                    _ if a.starts_with('-') => return Err(misuse(&format!("unknown option {a}"), "setup")),
                    _ if folder.is_none() => folder = Some(PathBuf::from(a)),
                    _ => return Err(misuse("setup takes one folder", "setup")),
                }
            }
            setup::run(folder.unwrap_or_else(|| ".".into()), yes)
        }
        Some("help") => match args.next() {
            None => {
                emit(help::MAIN);
                Ok(())
            }
            Some(c) => {
                emit(help::for_command(&c).ok_or_else(|| format!("quarry: no command \"{c}\". Run `quarry help`."))?);
                Ok(())
            }
        },
        None | Some("-h" | "--help") => {
            emit(help::MAIN);
            Ok(())
        }
        Some("version" | "-V" | "--version") => {
            emit(&format!("quarry {}\n", help::VERSION));
            Ok(())
        }
        Some(c) => Err(format!(
            "quarry: no command \"{c}\". To search, run: quarry search \"{c}{}\"\nRun `quarry help` for all commands.",
            args.map(|a| format!(" {a}")).collect::<String>()
        )),
    }
}

fn main() -> ExitCode {
    // Rust's default panic message can quote the string being sliced, which might hold a secret.
    std::panic::set_hook(Box::new(|_| eprintln!("quarry: internal error")));
    match dispatch(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
