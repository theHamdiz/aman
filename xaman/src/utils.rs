use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;
use console::style;

pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
            .template("{spinner:.green} {msg}")
            .expect("Invalid template"),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(120));
    pb
}

pub fn success(msg: &str) {
    println!("{} {}", style("✔").green(), msg);
}

pub fn warn(msg: &str) {
    println!("{} {}", style("⚠").yellow(), msg);
}

pub fn error(msg: &str) {
    eprintln!("{} {}", style("✘").red(), msg);
}

pub fn info(msg: &str) {
    println!("{} {}", style("ℹ").blue(), msg);
}
