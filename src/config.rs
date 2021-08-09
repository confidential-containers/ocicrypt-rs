// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// DecryptConfig wraps the Parameters map that holds the decryption key
#[derive(Debug, Default, Clone)]
pub struct DecryptConfig {
    /// map holding 'privkeys', 'x509s', 'gpg-privatekeys'
    pub param: HashMap<String, Vec<Vec<u8>>>,
}

impl DecryptConfig {
    /// Update DecryptConfig param with key and value
    fn update_param(&mut self, key: String, value: Vec<Vec<u8>>) -> Result<()> {
        if value.is_empty() {
            return Err(anyhow!("decrypt config: value of {} is None", key));
        }

        self.param
            .entry(key)
            .and_modify(|v| v.extend(value.iter().cloned()))
            .or_insert(value);

        Ok(())
    }

    /// Add DecryptConfig with configured private keys for decryption
    pub fn decrypt_with_priv_keys(
        &mut self,
        priv_keys: Vec<Vec<u8>>,
        priv_key_passwords: Vec<Vec<u8>>,
    ) -> Result<()> {
        if priv_keys.len() != priv_key_passwords.len() {
            return Err(anyhow!(
                "Length of privKeys should match with privKeysPasswords"
            ));
        }

        self.update_param("privkeys".to_string(), priv_keys)?;
        self.update_param("privkeys-passwords".to_string(), priv_key_passwords)?;

        Ok(())
    }

    /// Add DecryptConfig with configured x509 certs for decryption
    pub fn decrypt_with_x509s(&mut self, x509s: Vec<Vec<u8>>) -> Result<()> {
        self.update_param("x509s".to_string(), x509s)?;

        Ok(())
    }

    /// Add DecryptConfig with configured gpg private keys for decryption
    pub fn decrypt_with_gpg(
        &mut self,
        gpg_priv_keys: Vec<Vec<u8>>,
        gpg_priv_pwds: Vec<Vec<u8>>,
    ) -> Result<()> {
        self.update_param("gpg-privatekeys".to_string(), gpg_priv_keys)?;
        self.update_param("gpg-privatekeys-passwords".to_string(), gpg_priv_pwds)?;

        Ok(())
    }

    /// Add DecryptConfig with configured pkcs11 config and YAML formatted keys for decryption
    pub fn decrypt_with_pkcs11(
        &mut self,
        pkcs11_config: Vec<Vec<u8>>,
        pkcs11_yaml: Vec<Vec<u8>>,
    ) -> Result<()> {
        self.update_param("pkcs11-config".to_string(), pkcs11_config)?;
        self.update_param("pkcs11-yamls".to_string(), pkcs11_yaml)?;

        Ok(())
    }

    /// Add DecryptConfig with configured key_providers for decryption
    pub fn decrypt_with_key_provider(&mut self, key_providers: Vec<Vec<u8>>) -> Result<()> {
        for val in key_providers.iter().map(|v| String::from_utf8_lossy(v)) {
            if let Some(index) = val.find(':') {
                let key: String = val.chars().take(index).collect();
                let value: String = val.chars().skip(index + 1).collect();

                self.update_param(key, vec![value.as_bytes().to_vec()])?;
            } else {
                self.update_param(val.to_string(), vec![b"Enabled".to_vec()])?;
            }
        }

        Ok(())
    }
}

/// EncryptConfig is the container image PGP encryption configuration holding
/// the identifiers of those that will be able to decrypt the container and
/// the PGP public keyring file data that contains their public keys.
#[derive(Debug, Default, Clone)]
pub struct EncryptConfig {
    /// map holding 'gpg-recipients', 'gpg-pubkeyringfile', 'pubkeys', 'x509s'
    pub param: HashMap<String, Vec<Vec<u8>>>,

    /// Allow for adding wrapped keys to an encrypted layer
    pub decrypt_config: Option<DecryptConfig>,
}

impl EncryptConfig {
    /// Update EncryptConfig param with key and value
    fn update_param(&mut self, key: String, value: Vec<Vec<u8>>) -> Result<()> {
        if value.is_empty() {
            return Err(anyhow!("encrypt config: value of {} is None", key));
        }

        self.param
            .entry(key)
            .and_modify(|v| v.extend(value.iter().cloned()))
            .or_insert(value);

        Ok(())
    }

    /// Add EncryptConfig with jwe public keys for encryption
    pub fn encrypt_with_jwe(&mut self, pubkeys: Vec<Vec<u8>>) -> Result<()> {
        self.update_param("pubkeys".to_string(), pubkeys)?;

        Ok(())
    }

    /// Add EncryptConfig with pkcs7 x509 certs for encryption
    pub fn encrypt_with_pkcs7(&mut self, x509s: Vec<Vec<u8>>) -> Result<()> {
        self.update_param("x509s".to_string(), x509s)?;

        Ok(())
    }

    /// Add EncryptConfig with configured gpg parameters for encryption
    pub fn encrypt_with_gpg(
        &mut self,
        gpg_recipients: Vec<Vec<u8>>,
        gpg_pub_ring_file: Vec<u8>,
    ) -> Result<()> {
        self.update_param("gpg-recipients".to_string(), gpg_recipients)?;
        self.update_param("gpg-pubkeyringfile".to_string(), vec![gpg_pub_ring_file])?;

        Ok(())
    }

    /// Add EncryptConfig with configured pkcs11 parameters for encryption
    pub fn encrypt_with_pkcs11(
        &mut self,
        pkcs11_config: Vec<Vec<u8>>,
        pkcs11_pubkeys: Vec<Vec<u8>>,
        pkcs11_yaml: Vec<Vec<u8>>,
    ) -> Result<()> {
        if !pkcs11_pubkeys.is_empty() {
            self.update_param("pkcs11-pubkeys".to_string(), pkcs11_pubkeys)?;
        }

        if !pkcs11_yaml.is_empty() {
            self.update_param("pkcs11-config".to_string(), pkcs11_config)?;
            self.update_param("pkcs11-yamls".to_string(), pkcs11_yaml)?;
        }

        Ok(())
    }

    /// Add EncryptConfig with configured keyprovider parameters for encryption
    pub fn encrypt_with_key_provider(&mut self, key_providers: Vec<Vec<u8>>) -> Result<()> {
        for val in key_providers.iter().map(|v| String::from_utf8_lossy(v)) {
            if let Some(index) = val.find(':') {
                let key: String = val.chars().take(index).collect();
                let value: String = val.chars().skip(index + 1).collect();

                self.update_param(key, vec![value.as_bytes().to_vec()])?;
            } else {
                self.update_param(val.to_string(), vec![b"Enabled".to_vec()])?;
            }
        }

        Ok(())
    }
}

/// CryptoConfig is a common wrapper for EncryptConfig and DecrypConfig that can
/// be passed through functions that share much code for encryption and decryption
#[derive(Debug, Default, Clone)]
pub struct CryptoConfig {
    pub encrypt_config: Option<EncryptConfig>,
    pub decrypt_config: Option<DecryptConfig>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_config() {
        let priv_keys1 = vec![b"priv_key1".to_vec()];
        let priv_keys2 = vec![b"priv_key2".to_vec()];
        let priv_keys3 = vec![b"priv_key3".to_vec(), b"priv_key4".to_vec()];
        let pkcs11_config = vec![b"pkcs11_config".to_vec()];
        let pkcs11_yaml = vec![b"pkcs11_yaml".to_vec()];

        let key_providers = vec![
            b"key_p1".to_vec(),
            b"key_p2:abc".to_vec(),
            b"key_p3:abc:abc".to_vec(),
        ];

        let mut dc = DecryptConfig::default();

        assert!(dc
            .decrypt_with_priv_keys(priv_keys1.clone(), priv_keys2.clone())
            .is_ok());
        assert!(dc
            .decrypt_with_priv_keys(priv_keys1.clone(), priv_keys3.clone())
            .is_err());
        assert!(dc.decrypt_with_x509s(priv_keys1.clone()).is_ok());
        assert!(dc.decrypt_with_gpg(priv_keys1, priv_keys2).is_ok());
        assert!(dc
            .decrypt_with_pkcs11(pkcs11_config.clone(), pkcs11_yaml.clone())
            .is_ok());
        assert!(dc.decrypt_with_key_provider(key_providers).is_ok());
    }

    #[test]
    fn test_encrypt_config() {
        let pubkeys1 = vec![b"pubkey1".to_vec()];
        let pubkeys2 = vec![b"pubkey2".to_vec()];
        let gpg_recipients = vec![b"recip1".to_vec(), b"recip2".to_vec()];
        let gpg_pub_ring_file = b"gpg_pub_ring_file".to_vec();
        let pkcs11_config = vec![b"pkcs11_config".to_vec()];
        let pkcs11_pubkeys = vec![b"pkcs11_pubkeys".to_vec()];
        let pkcs11_yaml = vec![b"pkcs11_yaml".to_vec()];
        let key_providers = vec![
            b"key_p1".to_vec(),
            b"key_p2:abc".to_vec(),
            b"key_p3:abc:abc".to_vec(),
        ];

        let mut ec = EncryptConfig::default();

        assert!(ec.encrypt_with_jwe(vec![]).is_err());
        assert!(ec.encrypt_with_jwe(pubkeys1.clone()).is_ok());
        assert_eq!(pubkeys1.clone(), ec.param["pubkeys"]);

        assert!(ec.encrypt_with_jwe(pubkeys2.clone()).is_ok());
        assert_eq!(2, ec.param["pubkeys"].len());

        assert!(ec.encrypt_with_pkcs7(pubkeys2.clone()).is_ok());
        assert!(ec
            .encrypt_with_gpg(gpg_recipients.clone(), gpg_pub_ring_file.clone())
            .is_ok());
        assert_eq!(gpg_recipients, ec.param["gpg-recipients"]);
        assert_eq!(vec![gpg_pub_ring_file], ec.param["gpg-pubkeyringfile"]);

        assert!(ec
            .encrypt_with_pkcs11(pkcs11_config.clone(), pkcs11_pubkeys, pkcs11_yaml.clone())
            .is_ok());
        assert!(ec.encrypt_with_key_provider(key_providers.clone()).is_ok());
        assert_eq!(vec![b"Enabled".to_vec()], ec.param["key_p1"]);
        assert_eq!(vec![b"abc".to_vec()], ec.param["key_p2"]);
        assert_eq!(vec![b"abc:abc".to_vec()], ec.param["key_p3"]);
    }

    #[test]
    fn test_crypto_config() {
        let dc = DecryptConfig::default();
        let ec = EncryptConfig::default();
        let mut cc = CryptoConfig::default();

        assert!(cc.encrypt_config.is_none());
        assert!(cc.decrypt_config.is_none());
        cc.encrypt_config = Some(ec);
        cc.decrypt_config = Some(dc);
        assert!(cc.encrypt_config.is_some());
        assert!(cc.decrypt_config.is_some());
    }
}

// Pkcs11Config describes the layout of a pkcs11 config file
// The file has the following yaml format:
// module_directories:
// - /usr/lib64/pkcs11/
// allowed_module_paths:
// - /usr/lib64/pkcs11/libsofthsm2.so
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Pkcs11Config {
    pub module_directories: Vec<String>,
    pub allowed_module_paths: Vec<String>,
}

const CONFIGFILE: &str = "ocicrypt.conf";
const ENVVARNAME: &str = "OCICRYPT_CONFIG";
const XDGCONFIGHOME: &str = "XDG_CONFIG_HOME";
const HOME: &str = "HOME";

impl Pkcs11Config {
    fn get_configuration(&self) -> Result<Pkcs11Config> {
        match std::env::var(ENVVARNAME) {
            Ok(filename) => {
                if filename == "internal" {
                    return self.get_default_crypto_config_opts();
                }
                if std::path::Path::new(&filename).exists() {
                    return parse_config_file(filename);
                }
                // fall out of match
            }
            Err(std::env::VarError::NotPresent) => (), // fall out of match
            Err(std::env::VarError::NotUnicode(_)) => return Err(anyhow!("Invalid filename")),
        };

        match std::env::var(XDGCONFIGHOME) {
            Ok(envvar) => {
                let p: std::path::PathBuf = [envvar, CONFIGFILE.to_string()].iter().collect();
                if std::path::Path::new(&p).exists() {
                    return parse_config_file(p.to_str().unwrap().to_string());
                }
                // fall out of match
            }
            Err(std::env::VarError::NotPresent) => (), // fall out of match
            Err(std::env::VarError::NotUnicode(_)) => return Err(anyhow!("Invalid filename")),
        };

        match std::env::var(HOME) {
            Ok(envvar) => {
                let p: std::path::PathBuf = [envvar, ".config".to_string(), CONFIGFILE.to_string()]
                    .iter()
                    .collect();
                if std::path::Path::new(&p).exists() {
                    return parse_config_file(p.to_str().unwrap().to_string());
                }
                // fall out of match
            }
            Err(std::env::VarError::NotPresent) => (), // fall out of match
            Err(std::env::VarError::NotUnicode(_)) => return Err(anyhow!("Invalid filename")),
        }

        let p: std::path::PathBuf = ["/etc".to_string(), CONFIGFILE.to_string()]
            .iter()
            .collect();
        if std::path::Path::new(&p).exists() {
            return parse_config_file(p.to_str().unwrap().to_string());
        }
        Err(anyhow!(""))
    }

    fn get_default_crypto_config_opts(&self) -> Result<Pkcs11Config> {
        let mdyaml = get_default_module_directories_yaml("".to_string())?;

        let config = format!(
            "module-directories:\n\
                              {} \
                              allowed-module-paths:\n\
                              {}",
            mdyaml, mdyaml
        );
        parse_pkcs11_config_file(config.as_bytes())
    }

    fn get_user_pkcs11_config(&self) -> Result<Pkcs11Config> {
        let empty_config = Pkcs11Config {
            module_directories: vec![],
            allowed_module_paths: vec![],
        };
        let c = self.get_configuration()?;
        // TODO ? can we ever get an empty pkcs11config from get-configuration?
        // see go version's error handling here...
        Ok(c)
    }
}

fn parse_config_file(filename: String) -> Result<Pkcs11Config> {
    let data = std::fs::read_to_string(filename)?;
    let config: Pkcs11Config = serde_yaml::from_str(&data)?;
    Ok(config)
}

// Parse a pkcs11 config file that influences the module search behavior as
// well as the set of modules that users are allowed to use
pub fn parse_pkcs11_config_file(yamlstr: &[u8]) -> Result<Pkcs11Config> {
    let p11conf: Pkcs11Config = serde_yaml::from_slice(yamlstr)?;
    Ok(p11conf)
}

// GetDefaultModuleDirectories returns module directories covering
// a variety of Linux distros
fn get_default_module_directories() -> Result<Vec<String>> {
    let mut dirs = vec![
        "/usr/lib64/pkcs11/".to_string(), // Fedora,RHEL,openSUSE
        "/usr/lib/pkcs11/".to_string(),   // Fedora,ArchLinux
        "/usr/local/lib/pkcs11/".to_string(),
        "/usr/lib/softhsm/".to_string(), // Debian,Ubuntu
    ];

    // Debian directory: /usr/lib/(x86_64|aarch64|arm|powerpc64le|s390x)-linux-gnu/
    let hoq = get_host_and_os_type()?;
    let hosttype = hoq.0;
    let ostype = hoq.1;
    let q = hoq.2;
    if hosttype.len() > 0 {
        let dir = format!("/usr/lib/{}-{}-{}/", hosttype, ostype, q);
        dirs.push(dir);
    }
    Ok(dirs)
}
pub fn get_default_module_directories_yaml(indent: String) -> Result<String> {
    let mut res = "".to_string();
    for dir in get_default_module_directories()? {
        res += &format!("{}- {}\n", indent, dir).to_string();
    }
    Ok(res)
}

fn get_host_and_os_type() -> Result<(String, String, String)> {
    let mut ht = "";
    let mut ot = "";
    let mut st = "";
    match std::env::consts::OS {
        "linux" => {
            ot = "linux";
            st = "gnu";
            match std::env::consts::ARCH {
                "arm" => ht = "arm",
                "arm64" => ht = "aarch64",
                "amd64" => ht = "x86_64",
                "ppc64le" => ht = "powerpc64le",
                "s390x" => ht = "s390x",
                _ => (),
            }
            //return Ok((ht.to_string(), ot.to_string(), st.to_string()));
        }
        _ => (),
    }
    Ok((ht.to_string(), ot.to_string(), st.to_string()))
}
