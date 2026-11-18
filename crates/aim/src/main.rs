use clap::Parser;

fn main() {
    let cli = aim::cli::Cli::parse();
    match aim::cli::run(cli) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("aim: error: {err}");
            std::process::exit(1);
        }
    }
}
