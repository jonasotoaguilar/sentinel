use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();

    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => {
            let _ = writeln!(
                stderr,
                "sentinel: cannot resolve working directory: {error}"
            );
            return ExitCode::from(2);
        }
    };

    sentinel::run(&args, &cwd, &mut stdout.lock(), &mut stderr)
}
