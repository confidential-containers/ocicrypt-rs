
use anyhow::{anyhow, Result};
use tempdir::TempDir;
use std::process::Command;

use std::{thread, time};

const TEMPDIR_PREFIX: &str = "ocicrypt-rs";

pub struct SoftHSMSetup {
    pub statedir_path: String,
    pub statedir_folder: TempDir,
}


// A SoftHSM setup. Construct a new instance with ::new().
// Calling run() methods on the instance will invoke `softhsm_setup`
// Note: Use run_softhsm_setup() first before before calling other functions.
impl SoftHSMSetup {

    // Constructs a new SoftHSMSetup instance.
    pub fn new() -> Result<Self> {
        // create a temporary folder (deleted when instance goes out of scope)
        let statedir_folder = TempDir::new(TEMPDIR_PREFIX)?;
        // string of the temporary folder's path
        let statedir_path = statedir_folder.path().to_string_lossy().to_string();
        Ok(SoftHSMSetup{
            statedir_path: statedir_path,
            statedir_folder: statedir_folder,
        })
    }

    // Returns the path to the softhsm configuration file.
    pub fn get_config_filename(&self) -> Result<String> {
        Ok(format!("{}/softhsm2.conf", self.statedir_path).to_string())
    }

    // Invokes `softhsm_setup setup` and returns the public key that was
    // displayed
    pub fn run_softhsm_setup(&self, softhsm_setup: &String) -> Result<String> {
        let res = Command::new(softhsm_setup)
                          .arg("setup")
                          .env("SOFTHSM_SETUP_CONFIGDIR", &self.statedir_path)
                          .output()?;
        let res = String::from_utf8(res.stdout)?;
        match res.find("pkcs11:") {
            Some(idx) => {
                let trim_me: &[_] = &[' ', '\n'];
                let res = res[idx..].trim_end_matches(trim_me);
                return Ok(res.to_string());
            },
            None => return Err(anyhow!("Failed to find 'pkcs11:' in output 
                                       from `softhsm setup`")),
        };
    }

    // Invokes `softhsm_setup getpubkey` and returns the public key
    pub fn run_softhsm_get_pubkey(&self, softhsm_setup: &String) -> Result<String> {
        let res = Command::new(softhsm_setup)
                          .arg("getpubkey")
                          .env("SOFTHSM_SETUP_CONFIGDIR", &self.statedir_path)
                          .output()?;
        Ok(String::from_utf8(res.stdout)?)
    }

    // Invokes `softhsm_setup teardown`
    pub fn run_softhsm_teardown(&self, softhsm_setup: &String) -> Result<()> {
        let _ = Command::new(softhsm_setup)
                        .arg("teardown")
                        .env("SOFTHSM_SETUP_CONFIGDIR", &self.statedir_path)
                        .output()?;
        Ok(())
    }

}

#[cfg(test)]
mod softhsm_tests {
    use super::*;

    #[test]
    fn test_new() {
        match SoftHSMSetup::new() {
            Ok(_) => (),
            Err(_) => assert!(false),
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
            Ok(o) => (),
            Err(e) => assert!(false),
        };
    }
    
    //#[test]
    // FIXME commenting out for now b/c it's slow
    fn test_run_softhsm_get_pubkey() {
        let shsm_setup = SoftHSMSetup::new().unwrap();
        let path_to_script = env!("CARGO_MANIFEST_DIR").to_string() + "/scripts/softhsm_setup";

        // call run_softhsm_setup() first
        let rv = shsm_setup.run_softhsm_setup(&path_to_script);
        match rv {
            Ok(o) => (),
            Err(e) => assert!(false),
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
            Ok(o) => (),
            Err(e) => assert!(false),
        };

        shsm_setup.run_softhsm_teardown(&path_to_script).unwrap();
    }

}
