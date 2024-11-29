use std::io::Write as _;

use log::log_enabled;
use tokio::{
    task::JoinHandle,
    time::{interval, Duration},
};

pub fn print_dots() -> JoinHandle<()> {
    async fn print_dots_routine() {
        let mut interval = interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            if log_enabled!(log::Level::Error) {
                eprint!(".");
            }
            std::io::stderr().flush().unwrap();
        }
    }

    tokio::spawn(print_dots_routine())
}
