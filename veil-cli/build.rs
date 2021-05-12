use std::env;

use clap::IntoApp;
use clap_generate::generate_to;
use clap_generate::generators::{Bash, Fish, PowerShell, Zsh};

include!("src/cli.rs");

fn main() {
    if let Some(out_dir) = env::var_os("OUT_DIR") {
        let mut app = Opts::into_app();
        let app_name = "veil";
        generate_to::<Bash, _, _>(&mut app, app_name, &out_dir);
        generate_to::<Fish, _, _>(&mut app, app_name, &out_dir);
        generate_to::<PowerShell, _, _>(&mut app, app_name, &out_dir);
        generate_to::<Zsh, _, _>(&mut app, app_name, &out_dir);
    }
}
