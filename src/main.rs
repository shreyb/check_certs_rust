use std::io::{self, Write};
use std::path;
use std::process;
use std::{env, fs};

use clap::{ArgGroup, Command, arg};
use yaml_rust2::{Yaml, YamlLoader};

mod tests;

fn main() {
    let matches = create_command_with_args().get_matches();
    let args = RunArgs {
        filename: matches.get_one::<String>("filename"),
        accountname: matches.get_one::<String>("accountname"),
        experiment: matches.get_one::<String>("experiment"),
        config: matches.get_one::<String>("config"),
    };

    let root = env::current_dir().expect("Can't find current directory");
    let mut out = io::stdout(); // Set stdout

    if let Err(e) = run(args, &mut out, root) {
        println!("Error running check_cert: {e}")
    };
}

fn run<W>(args: RunArgs, stdout: &mut W, root: path::PathBuf) -> Result<(), String>
where
    W: Write,
{
    // 1. If filename is given, use that
    // 2. Look in config file
    // 2a. If certfile set, use that
    // 2b. If not set, construct cert path

    // 1.
    let filename: path::PathBuf;

    if let Some(val) = args.filename {
        filename = path::PathBuf::from(val)
    } else {
        let config = args
            .config
            .ok_or("Since filename is not specified, config should be specified")?;
        let experiment = args
            .experiment
            .ok_or("Since filename is not specified, experiment should be specified")?;
        let accountname = args
            .accountname
            .ok_or("Since filename is not specified, accountname should be specified")?;
        //
        filename = get_cert_path(root, config, experiment, accountname)?;
    }

    // Get our cert filename
    if let Err(e) = stdout.write_all(&format!("Filename: {}\n", filename.display()).as_bytes()) {
        return Err(format!("Could not write filename to stdout: {e}"));
    }

    if let Ok(exists) = filename.try_exists() {
        if !exists {
            return Err(format!("The file {} doesn't exist", filename.display()));
        }
    } else {
        return Err(format!("The file {} doesn't exist", filename.display()));
    }

    // Run the command
    let out = process::Command::new("openssl")
        .args([
            "x509",
            "-in",
            filename
                .to_str()
                .expect("Couldn't convert file_name to string"),
            "-noout",
            "-subject",
            "-dates",
            "-nameopt",
            "compat",
        ])
        .output();
    match out {
        Ok(_out) => {
            if let Err(e) = stdout.write(&_out.stdout) {
                return Err(format!("Could not write output to stdout {}", e));
            };
            if !_out.status.success() {
                return Err(format!(
                    "openssl command failed.  The input file {} is probably not a valid cert file.",
                    filename.display()
                ));
            }
        }
        Err(e) => return Err(format!("Could not run openssl command: {}", e)),
    };
    Ok(())
}

/// Holds the set of args to be sent to the run() func. Validation is done in run()
struct RunArgs<'a> {
    filename: Option<&'a String>,
    accountname: Option<&'a String>,
    experiment: Option<&'a String>,
    config: Option<&'a String>,
}

// Utility functions

/// Define our args to parse
fn create_command_with_args() -> Command {
    Command::new("check_cert")
        .arg_required_else_help(true)

        // Config/experiment/account arg group
        .arg(arg!(-c --config     <FILE>    "Configuration file")
            .requires("accountname")
            .requires("experiment")
            .default_value("/etc/managed-tokens/managedTokens.yml")
        )
        .arg(arg!(-e --experiment <EXPERIMENT>   "Experiment name from config file (must be used with -c/--config and -a/--accountname")
            .requires("config")
            .requires("accountname"))
        .arg(arg!(-a --accountname <ACCOUNTNAME>   "Account name from config file (must be used with -c/--config and -e/--experiment")
            .requires("config")
            .requires("experiment"))

        .arg(arg!(-f --filename  <FILE>   "Filename of certificate to check"))
        .group(ArgGroup::new("configfile_group")
            .args(["config", "accountname", "experiment"])
            .multiple(true)
            .conflicts_with("filename")
        )
}

/// Given configuration and arguments, return the path to the certificate of interest
fn get_cert_path(
    root: path::PathBuf,
    config: &String,
    experiment_name: &String,
    account_name: &String,
) -> Result<path::PathBuf, String> {
    // See if certfile is set in config file
    if let Some(val) = get_certfile_from_config(config, experiment_name, account_name)? {
        return Ok(path::PathBuf::from(val));
    }

    // Otherwise, construct the cert path
    let rel_path: path::PathBuf = ["certs", account_name].iter().collect();
    let mut acct_cert = path::PathBuf::from(root).join(rel_path);
    acct_cert.set_extension("cert");
    Ok(acct_cert)
}

/// Get the certfile from the configuration at the YAML key
/// experiments.<experiment_name>.certfile if the experiment.<experiment_name> structure has
/// <account_name> configured. If the certfile key is not set, return Ok(None)
fn get_certfile_from_config(
    config: &String,
    experiment_name: &String,
    account_name: &String,
) -> Result<Option<String>, String> {
    // Read config file in
    let config_string = match fs::read_to_string(path::PathBuf::from(config)) {
        Ok(val) => val,
        Err(e) => return Err(format!("Couldn't read YAML config to string: {e}")),
    };
    let config_yaml = match YamlLoader::load_from_str(&config_string) {
        Ok(val) => val,
        Err(e) => return Err(format!("Couldn't parse YAML: {e}")),
    };

    // Get experiment entry for later use
    let experiment_entry = config_yaml[0]
        .as_hash()
        .ok_or("Couldn't parse YAML at top level: YAML is not a dictionary as expected")?
        .get(&Yaml::from_str("experiments"))
        .ok_or("No experiments entry in YAML")?
        .as_hash()
        .ok_or("experiments entry is not a dictionary")?
        .get(&Yaml::from_str(&experiment_name))
        .ok_or(format!(
            "No experiment {experiment_name} found in experiments entry",
        ))?
        .as_hash()
        .ok_or(format!(
            "experiment {experiment_name} data is not a dictionary"
        ))?;

    // Look for the correct account name in our experiment entry. If we can't find it, return an
    // Err
    if !experiment_entry
        .get(&Yaml::from_str("accounts"))
        .ok_or(format!("No accounts entry in {experiment_name} config"))?
        .as_hash()
        .ok_or(format!(
            "accounts entry for experiment {experiment_name} is not a dictionary",
        ))?
        .contains_key(&Yaml::from_str(&account_name))
    {
        return Err(format!(
            "Could not find account {account_name} in {experiment_name} entry",
        ));
    }

    // We found our experiment_name and account_name. Now return the certfile key for the
    // experiment if we have it
    match experiment_entry.get(&Yaml::from_str("certfile")) {
        Some(val) => Ok(Some(
            val.as_str()
                .ok_or("certfile exists but is not a string")?
                .to_owned(),
        )),
        None => Ok::<Option<String>, String>(None),
    }
}
