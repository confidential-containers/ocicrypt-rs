use std::process::{Command, Stdio};
use anyhow::{Result};
use std::{fs, str};


pub struct SoftHSMSetup {
    statedir: String,
}

pub fn get_config_filename(s: &SoftHSMSetup) -> String {
    return String::from(s.statedir.clone() + "/softhsm2.conf");
}

impl SoftHSMSetup {

    // run_softhsm_setup runs 'softhsm_setup setup' and returns the public key that was displayed
    pub fn run_softhsm_setup(&self, softhsm_setup: &String) -> Result<String> {

        let child = Command::new(&softhsm_setup)
                        .arg("setup")
                        .env("SOFTHSM_SETUP_CONFIGDIR", self.statedir.clone())
                        .stdout(Stdio::piped())
                        .spawn()?;

        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(_) => {
                fs::remove_dir_all(self.statedir.clone())?;
                // return Err("");
                return Ok(String::new())            
            }
        };

        let output_string = str::from_utf8(&output.stdout)?;

        if !output_string.contains("pkcs11:") {
            fs::remove_dir_all(self.statedir.clone())?;
            // return Err(0) -- change to Err !!
            return Ok(String::new())            
        }

        return Ok(String::from(output_string.strip_suffix("\n ").unwrap()))
    }

    // run_softhsm_pub_key runs 'softhsm_setup getpubkey' and returns the public key
    pub fn run_softhsm_pub_key(&self, softhsm_setup: &String) -> Result<String> {
        let child = Command::new(&softhsm_setup)
                        .arg("getpubkey")
                        .env("SOFTHSM_SETUP_CONFIGDIR", self.statedir.clone())
                        .stdout(Stdio::piped())
                        .spawn()?;

        let output = child.wait_with_output().expect("Failed to read stdout");

        return Ok(String::from(str::from_utf8(&output.stdout).unwrap()))
    }

    // run_softhsm_teardown runs 'softhsm_setup teardown
    pub fn run_softhsm_teardown(&self, softhsm_setup: &String) -> Result<()> {
        Command::new(&softhsm_setup)
            .arg("teardown")
            .env("SOFTHSM_SETUP_CONFIGDIR", self.statedir.clone())
            .status()
            .expect("Failed to execute teardown command");

        fs::remove_dir_all(self.statedir.clone())?;
        Ok(())
    }


}