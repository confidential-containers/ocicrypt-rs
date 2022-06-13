// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use std::process::Command;
use tempdir::TempDir;

const TEMPDIR_PREFIX: &str = "ocicrypt-rs";

/// SoftHSMSetup is a struct and impl that acts as an interface to a
/// softhsm helper script. The script simplifies interaction with softhsm.
/// Currently the struct's only member is the temporary folder for softhsm.
pub struct SoftHSMSetup {
    pub statedir_folder: TempDir,
}

/// The SoftHSMSetup impl's run() methods invoke the `softhsm_setup` script.
/// Note: Use run_softhsm_setup() first before before calling other functions.
impl SoftHSMSetup {
    /// Construct a new SoftHSMSetup instance.
    pub fn new() -> Result<Self> {
        // create a temporary folder (deleted when instance goes out of scope)
        let statedir_folder = TempDir::new(TEMPDIR_PREFIX)?;
        Ok(SoftHSMSetup { statedir_folder })
    }

    /// Return the path to the softhsm configuration file.
    pub fn get_config_filename(&self) -> Result<String> {
        Ok(format!(
            "{}/softhsm2.conf",
            self.statedir_folder.path().to_string_lossy()
        ))
    }

    /// Invoke `softhsm_setup setup` and return the public key that was
    /// displayed
    pub fn run_softhsm_setup(&self, softhsm_setup: &str) -> Result<String> {
        let res = Command::new(softhsm_setup)
            .arg("setup")
            .env(
                "SOFTHSM_SETUP_CONFIGDIR",
                &self.statedir_folder.path().to_string_lossy().to_string(),
            )
            .output()?;
        let res = String::from_utf8(res.stdout)?;
        match res.find("pkcs11:") {
            Some(idx) => {
                let trim_me: &[_] = &[' ', '\n'];
                let res = res[idx..].trim_end_matches(trim_me);
                Ok(res.to_string())
            }
            None => Err(anyhow!(
                "Failed to find 'pkcs11:' in output \
                                       from `softhsm setup`"
            )),
        }
    }

    /// Invoke `softhsm_setup getpubkey` and return the public key.
    pub fn run_softhsm_get_pubkey(&self, softhsm_setup: &str) -> Result<String> {
        let res = Command::new(softhsm_setup)
            .arg("getpubkey")
            .env(
                "SOFTHSM_SETUP_CONFIGDIR",
                &self.statedir_folder.path().to_string_lossy().to_string(),
            )
            .output()?;
        Ok(String::from_utf8(res.stdout)?)
    }

    /// Invoke `softhsm_setup teardown`.
    pub fn run_softhsm_teardown(&self, softhsm_setup: &str) -> Result<()> {
        let _ = Command::new(softhsm_setup)
            .arg("teardown")
            .env(
                "SOFTHSM_SETUP_CONFIGDIR",
                &self.statedir_folder.path().to_string_lossy().to_string(),
            )
            .output()?;
        Ok(())
    }
}

/*#[cfg(test)]
mod softhsm_tests {
    use super::*;

    #[test]
    fn test_new() {
        match SoftHSMSetup::new() {
            Ok(_) => (),
            Err(_) => panic!(),
        }
    }

    #[test]
    fn test_get_config_filename() {
        let shsm_setup = SoftHSMSetup::new().unwrap();
        let filename = shsm_setup.get_config_filename().unwrap();
        assert!(filename.contains("softhsm2.conf"));
        assert!(filename.contains(("/tmp/".to_string() + TEMPDIR_PREFIX).as_str()));
    }

    #[test]
    fn test_run_softhsm_setup() {
        let shsm_setup = SoftHSMSetup::new().unwrap();
        let path_to_script = env!("CARGO_MANIFEST_DIR").to_string() + "/scripts/softhsm_setup";
        let rv = shsm_setup.run_softhsm_setup(&path_to_script);
        match rv {
            Ok(_) => (),
            Err(_) => panic!(),
        };
    }

    #[test]
    fn test_run_softhsm_get_pubkey() {
        let shsm_setup = SoftHSMSetup::new().unwrap();
        let path_to_script = env!("CARGO_MANIFEST_DIR").to_string() + "/scripts/softhsm_setup";

        // call run_softhsm_setup() first
        let rv = shsm_setup.run_softhsm_setup(&path_to_script);
        match rv {
            Ok(_) => (),
            Err(_) => panic!(),
        };

        let res = shsm_setup.run_softhsm_get_pubkey(&path_to_script).unwrap();
        assert!(res.contains("BEGIN PUBLIC KEY"));
        assert!(res.contains("END PUBLIC KEY"));
    }

    #[test]
    fn test_run_softhsm_teardown() {
        let shsm_setup = SoftHSMSetup::new().unwrap();
        let path_to_script = env!("CARGO_MANIFEST_DIR").to_string() + "/scripts/softhsm_setup";

        // call run_softhsm_setup() first
        let rv = shsm_setup.run_softhsm_setup(&path_to_script);
        match rv {
            Ok(_) => (),
            Err(_) => panic!(),
        };

        shsm_setup.run_softhsm_teardown(&path_to_script).unwrap();
    }
}*/
