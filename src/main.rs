use clap::Parser;
use std::env;
use std::io::{self, BufRead, Write};
use std::path;
use std::process::{self, exit};

// Check certificate file for Managed Proxies
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long)]
    accountname: Option<String>,

    #[arg(short, long)]
    filename: Option<String>,
}

// TODO: We got a lifetime error if root is just a path::PathBuf.  Come back and see if it makes
// sense to assign a lifetime
fn get_cert_path(
    root: path::PathBuf,
    account_name: Option<String>,
    file_name: Option<String>,
) -> Result<path::PathBuf, String> {
    match (account_name, file_name) {
        (Some(val), None) => {
            let rel_path: path::PathBuf = ["certs", &val].iter().collect();
            let mut acct_cert = path::PathBuf::from(root).join(rel_path);
            acct_cert.set_extension("cert");
            Ok(acct_cert)
        }
        (None, Some(val)) => Ok([val.as_str()].iter().collect()),
        (Some(_), Some(_)) => Err(String::from(
            "Only one of account_name or file_name can be specified",
        )),
        (None, None) => Err(String::from(
            "Must specify one of account_name or file_name",
        )),
    }
}

fn main() {
    // Parse arguments
    let args = Args::parse();

    // Find path of cert file
    let root = env::current_dir().expect("Can't find current directory");
    let file_name = get_cert_path(root, args.accountname, args.filename).unwrap();

    file_name
        .try_exists()
        .expect("The file {file_name} doesn't exist");

    println!("Filename: {}", file_name.display());

    // Run the command
    let out = process::Command::new("openssl")
        .args([
            "x509",
            "-in",
            file_name
                .to_str()
                .expect("Couldn't convert file_name to string"),
            "-noout",
            "-subject",
            "-dates",
            "-nameopt",
            "compat",
        ])
        .output()
        .expect("Could not run openssl command");

    if !out.status.success() {
        println!(
            "openssl command failed.  The input file {} is probably not a valid cert file.",
            file_name.display()
        );
        exit(1);
    }

    io::stdout()
        .write_all(&out.stdout)
        .expect("Could not write command output to stdout");
}

fn run<R, W>(args: Args, stdout: &mut W) -> Result<(), String>
where
    W: Write,
{
    Ok(())
}

// TODO: Future - check config file and for expt, role combo, get cert used
//
#[cfg(tests)]
mod tests {

    fn get_cert_path_acct_ok() {}
    fn get_cert_path_filename_ok() {}
    fn get_cert_path_acct_and_filename_err() {}
    fn get_cert_path_neither_acct_and_filename_err() {}

    fn run_get_cert_path_panic() {}
    #[test]
    fn run_with_mocked_openssl() {}
    #[test]
    fn run_with_good_cert() {}

    fn run_with_bad_cert() {}

    fn run_with_bad_writer() {}
}
