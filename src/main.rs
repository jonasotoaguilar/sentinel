use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cwd = std::env::current_dir().unwrap_or_default();
    sentinel::run(
        &args,
        &cwd,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}
