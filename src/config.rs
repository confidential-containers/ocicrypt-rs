// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// CryptoConfig holding the identifiers and public/private key file data
/// that will be able to encrypt/decrypt the symmetric key
#[derive(Debug)]
pub struct CryptoConfig {
    /// encrypt map holding 'gpg-recipients', 'gpg-pubkeyringfile', 'pubkeys', 'enc-x509s'
    /// decrypt map holding 'privkeys', 'dec-x509s', 'gpg-privatekeys'
    pub param: HashMap<String, Vec<Vec<u8>>>,
}

impl CryptoConfig {
    /// Return a new CryptoConfig instance.
    pub fn new() -> Self {
        CryptoConfig {
            param: HashMap::new(),
        }
    }

    /// Update CryptoConfig param with key and value
    fn update_param(&mut self, key: String, value: Vec<Vec<u8>>) -> Result<()> {
        if value.len() == 0 {
            return Err(anyhow!("update_param: value of {} is None", key));
        }

        self.param
            .entry(key)
            .and_modify(|v| v.extend(value.iter().cloned()))
            .or_insert(value);

        Ok(())
    }

    /// Add CryptoConfig with jwe public keys for encryption
    pub fn encrypt_with_jwe(&mut self, pubkeys: Vec<Vec<u8>>) -> Result<()> {
        self.update_param("pubkeys".to_string(), pubkeys)?;

        Ok(())
    }

    /// Add CryptoConfig with pkcs7 x509 certs for encryption
    pub fn encrypt_with_pkcs7(&mut self, x509s: Vec<Vec<u8>>) -> Result<()> {
        self.update_param("enc-x509s".to_string(), x509s)?;

        Ok(())
    }

    /// Add CryptoConfig with configured gpg parameters for encryption
    pub fn encrypt_with_gpg(
        &mut self,
        gpg_recipients: Vec<Vec<u8>>,
        gpg_pub_ring_file: Vec<u8>,
    ) -> Result<()> {
        self.update_param("gpg-recipients".to_string(), gpg_recipients)?;
        self.update_param("gpg-pubkeyringfile".to_string(), vec![gpg_pub_ring_file])?;

        Ok(())
    }

    /// Add CryptoConfig with configured pkcs11 parameters for encryption
    pub fn encrypt_with_pkcs11(
        &mut self,
        pkcs11_config: Vec<Vec<u8>>,
        pkcs11_pubkeys: Vec<Vec<u8>>,
        pkcs11_yaml: Vec<Vec<u8>>,
    ) -> Result<()> {
        if pkcs11_pubkeys.len() > 0 {
            self.update_param("pkcs11-pubkeys".to_string(), pkcs11_pubkeys)?;
        }

        if pkcs11_yaml.len() > 0 {
            self.update_param("pkcs11-config".to_string(), pkcs11_config)?;
            self.update_param("pkcs11-yamls".to_string(), pkcs11_yaml)?;
        }

        Ok(())
    }

    /// Add CryptoConfig with configured keyprovider parameters for encryption
    pub fn encrypt_with_key_provider(&mut self, key_providers: Vec<Vec<u8>>) -> Result<()> {
        for val in key_providers.iter().map(|v| String::from_utf8_lossy(v)) {
            if let Some(index) = val.find(":") {
                let key: String = val.chars().take(index).collect();
                let value: String = val.chars().skip(index + 1).collect();

                self.update_param(key, vec![value.as_bytes().to_vec()])?;
            } else {
                self.update_param(val.to_string(), vec![b"Enabled".to_vec()])?;
            }
        }

        Ok(())
    }

    /// Add CryptoConfig with configured private keys for decryption
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

    /// Add CryptoConfig with configured x509 certs for decryption
    pub fn decrypt_with_x509s(&mut self, x509s: Vec<Vec<u8>>) -> Result<()> {
        self.update_param("dec-x509s".to_string(), x509s)?;

        Ok(())
    }

    /// Add CryptoConfig with configured gpg private keys for decryption
    pub fn decrypt_with_gpg(
        &mut self,
        gpg_priv_keys: Vec<Vec<u8>>,
        gpg_priv_pwds: Vec<Vec<u8>>,
    ) -> Result<()> {
        self.update_param("gpg-privatekeys".to_string(), gpg_priv_keys)?;
        self.update_param("gpg-privatekeys-passwords".to_string(), gpg_priv_pwds)?;

        Ok(())
    }

    /// Add CryptoConfig with configured pkcs11 config and YAML formatted keys for decryption
    pub fn decrypt_with_pkcs11(
        &mut self,
        pkcs11_config: Vec<Vec<u8>>,
        pkcs11_yaml: Vec<Vec<u8>>,
    ) -> Result<()> {
        self.update_param("pkcs11-config".to_string(), pkcs11_config)?;
        self.update_param("pkcs11-yamls".to_string(), pkcs11_yaml)?;

        Ok(())
    }

    /// Add CryptoConfig with configured key_providers for decryption
    pub fn decrypt_with_key_provider(&mut self, key_providers: Vec<Vec<u8>>) -> Result<()> {
        return self.encrypt_with_key_provider(key_providers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_config() {
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

        let priv_keys1 = vec![b"priv_key1".to_vec()];
        let priv_keys2 = vec![b"priv_key2".to_vec()];
        let priv_keys3 = vec![b"priv_key3".to_vec(), b"priv_key4".to_vec()];

        let mut cc = CryptoConfig::new();

        assert!(cc.encrypt_with_jwe(vec![]).is_err());
        assert!(cc.encrypt_with_jwe(pubkeys1.clone()).is_ok());
        assert_eq!(pubkeys1.clone(), cc.param["pubkeys"]);

        assert!(cc.encrypt_with_jwe(pubkeys2.clone()).is_ok());
        assert_eq!(2, cc.param["pubkeys"].len());

        assert!(cc.encrypt_with_pkcs7(pubkeys2.clone()).is_ok());
        assert!(cc
            .encrypt_with_gpg(gpg_recipients.clone(), gpg_pub_ring_file.clone())
            .is_ok());
        assert_eq!(gpg_recipients, cc.param["gpg-recipients"]);
        assert_eq!(vec![gpg_pub_ring_file], cc.param["gpg-pubkeyringfile"]);

        assert!(cc
            .encrypt_with_pkcs11(pkcs11_config.clone(), pkcs11_pubkeys, pkcs11_yaml.clone())
            .is_ok());
        assert!(cc.encrypt_with_key_provider(key_providers.clone()).is_ok());
        assert_eq!(vec![b"Enabled".to_vec()], cc.param["key_p1"]);
        assert_eq!(vec![b"abc".to_vec()], cc.param["key_p2"]);
        assert_eq!(vec![b"abc:abc".to_vec()], cc.param["key_p3"]);

        assert!(cc
            .decrypt_with_priv_keys(priv_keys1.clone(), priv_keys2.clone())
            .is_ok());
        assert!(cc
            .decrypt_with_priv_keys(priv_keys1.clone(), priv_keys3.clone())
            .is_err());
        assert!(cc.decrypt_with_x509s(priv_keys1.clone()).is_ok());
        assert!(cc.decrypt_with_gpg(priv_keys1, priv_keys2).is_ok());
        assert!(cc
            .decrypt_with_pkcs11(pkcs11_config.clone(), pkcs11_yaml.clone())
            .is_ok());
        assert!(cc.decrypt_with_key_provider(key_providers).is_ok());
        println!("final crypto config is: {:?}", cc);
    }
}
