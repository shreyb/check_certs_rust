use clap::{ArgGroup, Command, arg};
use std::env;
use std::io::{self, Write};
use std::path;
use std::process;

// TODO: Future - check config file and for expt, role combo, get cert used

fn create_command_with_args() -> Command {
    Command::new("check_cert")
        .arg_required_else_help(true)
        .arg(arg!(-c --config     <FILE>    "Configuration file")
            .requires("accountname"))
        .arg(arg!(-a --accountname <ACCOUNTNAME>   "Account name from config file (must be used with -c/--config")
            .requires("config"))
        .arg(arg!(-f --filename  <FILE>   "Filename of certificate to check"))
        .group(ArgGroup::new("configfile_group")
            .args(["config", "accountname"])
            .multiple(true)
            .conflicts_with("filename")
        )
}

struct RunArgs<'a> {
    filename: Option<&'a String>,
    accountname: Option<&'a String>,
}

fn get_cert_path(
    root: path::PathBuf,
    account_name: Option<&String>,
    file_name: Option<&String>,
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
    // let args = Args::parse();
    let matches = create_command_with_args().get_matches();
    let args = RunArgs {
        filename: matches.get_one::<String>("filename"),
        accountname: matches.get_one::<String>("accountname"),
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
    // Get our cert filename
    let filename = get_cert_path(root, args.accountname, args.filename)?;
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

#[cfg(test)]
mod tests {
    use std::{fs::File, path::PathBuf};

    use tmp_env;

    use super::*;

    #[test]
    fn get_cert_path_acct_ok() {
        let res = get_cert_path(
            path::PathBuf::from("fakeroot"),
            Some(&String::from("account")),
            None,
        );
        let expected: path::PathBuf = ["fakeroot", "certs", "account.cert"].iter().collect();
        assert_eq!(res, Ok(expected));
    }

    #[test]
    fn get_cert_path_filename_ok() {
        let res = get_cert_path(
            path::PathBuf::from("fakeroot"),
            None,
            Some(&String::from("path_to_file")),
        );
        assert_eq!(res, Ok(path::PathBuf::from("path_to_file")));
    }

    #[test]
    fn get_cert_path_acct_and_filename_err() {
        let res = get_cert_path(
            path::PathBuf::from("fakeroot"),
            Some(&String::from("account")),
            Some(&String::from("path_to_file")),
        );
        assert_eq!(
            res,
            Err(String::from(
                "Only one of account_name or file_name can be specified"
            ))
        );
    }

    #[test]
    fn get_cert_path_neither_acct_and_filename_err() {
        let res = get_cert_path(path::PathBuf::from("fakeroot"), None, None);
        assert_eq!(
            res,
            Err(String::from(
                "Must specify one of account_name or file_name",
            ))
        );
    }

    #[test]
    fn run_get_cert_path_propagate_err() {
        let args = RunArgs {
            accountname: None,
            filename: None,
        };
        let mut out = std::io::Cursor::new(vec![]);
        match run(args, &mut out, path::PathBuf::from("fakeroot")) {
            Err(e) => assert_eq!(
                e,
                String::from("Must specify one of account_name or file_name",)
            ),
            Ok(_) => panic!("Should have gotten an Err"),
        }
    }

    #[test]
    fn run_get_cert_path_file_dne_err() {
        let args = RunArgs {
            accountname: None,
            filename: Some(&String::from("fake_file")),
        };
        let mut out = std::io::Cursor::new(vec![]);
        match run(args, &mut out, path::PathBuf::from("fakeroot")) {
            Err(e) => assert_eq!(e, String::from("The file fake_file doesn't exist",)),
            Ok(_) => panic!("Should have gotten an Err"),
        }
    }

    #[test]
    fn run_with_mocked_openssl() -> Result<(), String> {
        // This test returns a Result and tries not to panic so that the tempdir can be deleted
        // once the test is finished and the variable dir goes out of scope

        // Create tempdir and point PATH there, with no openssl executable
        let dir = tmp_env::create_temp_dir().expect("Cannot create temp dir");
        let _tmp_env = tmp_env::set_var("PATH", dir.as_path());

        // Create the file that we'll be fake-reading
        let filename = PathBuf::from(dir.as_path()).join("myfile");
        match File::create_new(filename.as_path()) {
            Err(e) => return Err(String::from(e.to_string())),
            Ok(val) => val,
        };

        let val: String;
        let args = RunArgs {
            accountname: None,
            filename: Some({
                match filename.into_os_string().into_string() {
                    Ok(_val) => {
                        val = _val.clone();
                        &val
                    }
                    Err(_) => return Err(String::from("Could not convert filename into string")),
                }
            }),
        };
        let mut out = std::io::Cursor::new(vec![]);

        if let Err(e) = run(args, &mut out, path::PathBuf::from("fakeroot")) {
            if !e.contains("Could not run openssl command") {
                return Err(String::from(
                    "Should have gotten error message \"Could not run openssl command\". Got error {e}",
                ));
            }
        } else {
            return Err(String::from(
                "Should have gotten error message \"Could not run openssl command\"",
            ));
        }
        Ok(())
    }

    struct BadWriter {}

    impl Write for BadWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "error writing"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "error flushing"))
        }
    }

    #[test]
    fn run_with_mocked_bad_writer_good_cert_err() {
        let filename = env::current_dir()
            .expect("Can't find current directory")
            .join("certs")
            .join("acct.cert")
            .into_os_string()
            .into_string()
            .expect("Couldn't convert Path into String");

        let args = RunArgs {
            accountname: None,
            filename: Some(&filename),
        };
        let mut out = BadWriter {};

        if let Err(e) = run(args, &mut out, path::PathBuf::from("fakeroot")) {
            if !e.contains("Could not write filename to stdout") {
                panic!(
                    "Should have gotten error message \"Could not write filename to stdout\". Got error {e}"
                );
            }
        } else {
            panic!("Should have gotten error message \"Could not write filename to stdout\".",);
        }
    }

    #[test]
    fn run_with_good_cert() {
        let root = env::current_dir().expect("Can't find current directory");
        let filename = root
            .join("test_files")
            .join("acct.cert")
            .into_os_string()
            .into_string()
            .expect("Couldn't convert Path into String");

        let _filename = filename.clone();
        let args = RunArgs {
            accountname: None,
            filename: Some(&filename),
        };
        let mut out = std::io::Cursor::new(vec![]);

        let _ = run(args, &mut out, root).expect("Should not have gotten error");
        let expected_out = format!("Filename: {}\n", _filename).to_owned() + 
"subject=/DC=org/DC=incommon/C=US/ST=Illinois/O=Fermi Forward Discovery Group, LLC/CN=jobsub-test.fnal.gov
notBefore=Oct 10 00:00:00 2025 GMT
notAfter=Nov  9 23:59:59 2026 GMT
";
        assert_eq!(out.into_inner(), expected_out.as_bytes());
    }

    #[test]
    fn run_with_bad_cert() {
        let root = env::current_dir().expect("Can't find current directory");
        let filename = root
            .join("test_files")
            .join("blah.cert")
            .into_os_string()
            .into_string()
            .expect("Couldn't convert Path into String");

        let _filename = filename.clone();
        let args = RunArgs {
            accountname: None,
            filename: Some(&filename),
        };
        let mut out = std::io::Cursor::new(vec![]);

        match run(args, &mut out, root) {
            Ok(_) => panic!("Should have gotten an error"),
            Err(e) => assert_eq!(
                e.to_string(),
                format!(
                    "openssl command failed.  The input file {} is probably not a valid cert file.",
                    _filename
                )
            ),
        }
    }
}
