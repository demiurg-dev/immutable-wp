fn main() -> std::process::ExitCode {
    iwp::cli::run(std::env::args_os().collect())
}
