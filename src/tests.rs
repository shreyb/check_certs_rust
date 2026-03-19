#[cfg(test)]
mod tests {
    use crate::*;

    use log::info;
    use std::{fs::File, path::PathBuf};

    use test_log::test;
    use tmp_env::{self, TmpDir, create_temp_dir};

    fn tmp_dir_with_config(s: &str) -> TmpDir {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(s.as_bytes())
            .expect("Couldn't write data to file");
        tmp_path
    }

    #[test]
    fn get_cert_path_config_file() {
        let tmp_path = tmp_dir_with_config(
            "experiments:
    experiment:
        accounts:
            account: role
            foo: bar
        certfile: pathtofile",
        );
        assert_eq!(
            get_cert_path(
                path::PathBuf::from("fakeroot"),
                &String::from(tmp_path.as_path().join("fake_config.yml").to_str().unwrap()),
                &String::from("experiment"),
                &String::from("account"),
            ),
            Ok(path::PathBuf::from("pathtofile"))
        );
    }
    #[test]
    fn get_cert_path_config_file_err() {
        let tmp_path = tmp_dir_with_config("foo: bar");
        assert_eq!(
            get_cert_path(
                path::PathBuf::from("fakeroot"),
                &String::from(tmp_path.as_path().join("fake_config.yml").to_str().unwrap()),
                &String::from("experiment"),
                &String::from("account"),
            ),
            Err(String::from("No experiments entry in YAML"))
        );
    }
    #[test]
    fn get_cert_path_construct() {
        let tmp_path = tmp_dir_with_config(
            "experiments:
    experiment:
        accounts:
            account: role
            foo: bar",
        );
        let res = get_cert_path(
            path::PathBuf::from("fakeroot"),
            &String::from(tmp_path.as_path().join("fake_config.yml").to_str().unwrap()),
            &String::from("experiment"),
            &String::from("account"),
        );
        let expected: path::PathBuf = ["fakeroot", "certs", "account.cert"].iter().collect();
        assert_eq!(res, Ok(expected));
    }

    #[test]
    fn run_get_cert_path_config_experiment_accountname_not_specified() {
        struct TestArgs<'a> {
            config: Option<&'a String>,
            experiment: Option<&'a String>,
            accountname: Option<&'a String>,
        }

        let some_config = Some(&String::from("config"));
        let some_expt = Some(&String::from("expt"));
        let some_acct = Some(&String::from("acct"));

        let test_cases: Vec<TestArgs> = vec![
            TestArgs {
                config: None,
                experiment: some_expt,
                accountname: some_acct,
            },
            TestArgs {
                config: some_config,
                experiment: None,
                accountname: some_acct,
            },
            TestArgs {
                config: some_config,
                experiment: some_expt,
                accountname: None,
            },
        ];

        for test in test_cases {
            let args = RunArgs {
                accountname: test.accountname,
                filename: None,
                experiment: test.experiment,
                config: test.config,
            };
            let mut out = std::io::Cursor::new(vec![]);
            assert!(
                run(args, &mut out, path::PathBuf::from("fakeroot"))
                    .is_err_and(|e| e.contains("Since filename is not specified")
                        && e.contains("should be specified"))
            )
        }
    }

    #[test]
    fn run_get_cert_path_file_dne_err() {
        let args = RunArgs {
            accountname: None,
            filename: Some(&String::from("fake_file")),
            experiment: None,
            config: None,
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
        let dir = create_temp_dir().expect("Cannot create temp dir");
        let _tmp_env = tmp_env::set_var("PATH", dir.as_path());

        // Create the file that we'll be fake-reading
        let filename = PathBuf::from(dir.as_path()).join("myfile");
        if let Err(e) = File::create_new(filename.as_path()) {
            return Err(String::from(e.to_string()));
        };

        let val: String;
        let args = RunArgs {
            accountname: None,
            config: None,
            experiment: None,
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
            experiment: None,
            config: None,
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

    #[test_log::test]
    fn run_with_good_cert() {
        let root = env::current_dir().expect("Can't find current directory");
        let filename = root
            .join("test_files")
            .join("good.cert")
            .into_os_string()
            .into_string()
            .expect("Couldn't convert Path into String");

        if !path::PathBuf::from(&filename).exists() {
            info!(
                "Good cert file doesn't exist at test_files/good.cert. Generate a self-signed cert with subject /CN=test.example.com and install it at test_files/good.cert. Skipping test"
            );
            return;
        }

        let _filename = filename.clone();
        let args = RunArgs {
            config: None,
            experiment: None,
            accountname: None,
            filename: Some(&filename),
        };
        let mut out = std::io::Cursor::new(vec![]);

        let _ = run(args, &mut out, root).expect("Should not have gotten error");

        let output = String::from_utf8(out.into_inner()).unwrap();
        assert!(output.contains(format!("Filename: {}\n", _filename).as_str()));
        assert!(output.contains("subject=/CN=test.example.com"));
        assert!(output.contains("notBefore"));
        assert!(output.contains("notAfter"));
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
            config: None,
            experiment: None,
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

    // TODO: See if we can consolidate some of this code so we're not repeating
    #[test]
    fn check_config_bad_file() {
        // Bogus file
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x.contains("Couldn't read YAML config to string"))
        );
    }

    #[test]
    fn check_config_bad_yaml() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all("foo: bar:".as_bytes())
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x.contains("Couldn't parse YAML"))
        );
    }

    #[test]
    fn check_config_yaml_not_dict() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all("foobar".as_bytes())
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x
                == String::from(
                    "Couldn't parse YAML at top level: YAML is not a dictionary as expected"
                ))
        );
    }

    #[test]
    fn check_config_yaml_doesnt_have_experiments() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(
                "foo:
    bar"
                .as_bytes(),
            )
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x == String::from("No experiments entry in YAML"))
        );
    }

    #[test]
    fn check_config_yaml_experiments_not_dict() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(
                "experiments:
    bar"
                .as_bytes(),
            )
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x == String::from("experiments entry is not a dictionary"))
        );
    }

    #[test]
    fn check_config_yaml_experiments_no_experiment() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(
                "experiments:
    experiment_different:
        blah"
                    .as_bytes(),
            )
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(
                |x| x == String::from("No experiment experiment found in experiments entry")
            )
        );
    }

    #[test]
    fn check_config_yaml_experiments_experiment_not_dict() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(
                "experiments:
    experiment:
        blah"
                    .as_bytes(),
            )
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x == String::from("experiment experiment data is not a dictionary"))
        );
    }

    #[test]
    fn check_config_yaml_experiments_experiment_no_accounts() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(
                "experiments:
    experiment:
        foo:
            bar"
                .as_bytes(),
            )
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x == String::from("No accounts entry in experiment config"))
        );
    }

    #[test]
    fn check_config_yaml_experiments_experiment_no_accounts_dict() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(
                "experiments:
    experiment:
        accounts:
            bar"
                .as_bytes(),
            )
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x
                == String::from("accounts entry for experiment experiment is not a dictionary",))
        );
    }

    #[test]
    fn check_config_yaml_experiments_experiment_account_no_certfile() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(
                "experiments:
    experiment:
        accounts:
            account: role
            foo: bar"
                    .as_bytes(),
            )
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_ok_and(|x| x.is_none())
        );
    }

    #[test]
    fn check_config_yaml_experiments_experiment_account_certfile_not_str() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(
                "experiments:
    experiment:
        accounts:
            account: role
            foo: bar
        certfile: 4
"
                .as_bytes(),
            )
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x == String::from("certfile exists but is not a string"))
        );
    }

    #[test]
    fn check_config_yaml_no_accountname_for_expt() {
        let tmp_path = create_temp_dir().expect("Couldn't create temp dir");
        let filename = PathBuf::from(tmp_path.as_path()).join("fake_config.yml");
        File::create_new(filename.as_path())
            .expect("Couldn't create new temp file for config")
            .write_all(
                "experiments:
    experiment:
        accounts:
            account2: role
            foo: bar
        certfile: 4
"
                .as_bytes(),
            )
            .expect("Couldn't write data to file");

        assert!(
            get_certfile_from_config(
                &String::from(
                    filename
                        .as_path()
                        .to_str()
                        .expect("Couldn't convert tmp_file filename to string"),
                ),
                &String::from("experiment"),
                &String::from("account"),
            )
            .is_err_and(|x| x == String::from("Could not find account account in experiment entry"))
        );
    }
    #[test]
    fn check_get_certfile_from_config() {
        let res = get_certfile_from_config(
            &String::from("test_files/managedProxies.yml"),
            &String::from("experiment3"),
            &String::from("accountname"),
        )
        .expect("shouldn't cause an error");

        assert!(res.is_some_and(|x| x == String::from("/path/to/nondefault/cert")));
    }
}
