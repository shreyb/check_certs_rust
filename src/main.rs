use std::env;
use std::process;
use std::path;
use std::string;
use clap::Parser;

/// Check certificate file for Managed Proxies
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    accountname: Option<String>,


    #[arg(short, long)]
    filename: Option<String>,

}

fn main() {
    // Parse arguments
    let args = Args::parse();

    if args.accountname.is_none() & args.filename.is_none() {
        println!("Must specify either --accountname or --filename");
        process::exit(1);
    }

    if args.accountname.is_some() & args.filename.is_some() {
        println!("Must specify either --accountname or --filename");
        process::exit(1);
    }

    // Find path of cert file
    let root = env::current_dir().expect("Can't find current directory");
    let file_name: path::PathBuf = if args.accountname.is_some() {
        let rel_path: path::PathBuf = ["certs", args.accountname.expect("accountname should be something").as_str()].iter().collect();
        let mut a = root.join(rel_path);
        a.set_extension("cert");
        a
    } else if args.filename.is_some() {
        [args.filename.expect("filename should be something").as_str()].iter().collect()
    } else {
        println!("One of accountname or filename should be specified");
        process::exit(1);
    };

    let _x = file_name.display();
    if !file_name.try_exists().expect("Can't check existence of {_x}") {
        println!("The file {_x} doesn't exist");
        process::exit(1);
    }

    println!("Filename: {_x}");

    // Run the command
    let out = process::Command::new("openssl")
            .args([
                "x509",
                "-in", file_name.to_str().expect("Couldn't convert file_name to string"),
                "-noout", "-subject", "-dates",
                "-nameopt", "compat"])
            .output()
            .expect("Could not run openssl command");

   let stdout = string::String::from_utf8(out.stdout).expect("Couldn't convert stdout from utf8");
   print!("{}", stdout);


}

// TODO: Future - check config file and for expt, role combo, get cert used


