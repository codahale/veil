use std::env;

use clap::IntoApp;
use clap_generate::generate_to;
use clap_generate::generators::{Bash, Fish, PowerShell, Zsh};

include!("src/cli.rs");

fn main() {
    if let Some(out_dir) = env::var_os("CARGO_BUILD_TARGET_DIR") {
        let mut app = Opts::into_app();
        let app_name = "veil";
        generate_to(Bash, &mut app, app_name, &out_dir).expect("bash");
        generate_to(Fish, &mut app, app_name, &out_dir).expect("fish");
        generate_to(PowerShell, &mut app, app_name, &out_dir).expect("powershell");
        generate_to(Zsh, &mut app, app_name, &out_dir).expect("zsh");
    }
}
