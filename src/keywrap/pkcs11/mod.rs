use crate::config::{
    get_default_module_directories_yaml, parse_pkcs11_config_file, CryptoConfig, DecryptConfig,
    EncryptConfig, Pkcs11Config,
};
use crate::keywrap::KeyWrapper;
use crate::pkcs11_uri_wrapped::Pkcs11UriWrapped;
use crate::softhsm::SoftHSMSetup;
use crate::utils::{
    decrypt_pkcs11, encrypt_multiple, parse_private_key, parse_public_key, KeyType,
};
use anyhow::{anyhow, Result};
use pkcs11_uri::Pkcs11Uri;
use rsa::RsaPublicKey;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Pkcs11KeyWrapper {}

// Pkcs11KeyFileObject is a representation of the Pkcs11KeyFile with the pkcs11
// URI wrapper as an object
pub struct Pkcs11KeyFileObject {
    pub uriw: Pkcs11UriWrapped,
}

impl KeyWrapper for Pkcs11KeyWrapper {
    // Wrap the session key for recpients and encrypt the opts_data,
    // which describe the symmetric key used for encrypting the layer
    fn wrap_keys(&self, ec: &EncryptConfig, opts_data: &[u8]) -> Result<Vec<u8>> {
        let mut pubkeys: Vec<Vec<u8>> = Vec::new();
        if let Some(pks) = ec.param.get("pkcs11-pubkeys") {
            pubkeys.extend(pks.clone());
        }
        if let Some(yamls) = ec.param.get("pkcs11-yamls") {
            pubkeys.extend(yamls.clone());
        };
        let decrypt_config_pubkeys = match ec.decrypt_config.as_ref() {
            Some(x) => x,
            None => {
                return Err(anyhow!(
                    "EncryptConfig is missing
                                        decrypt_config member"
                ))
            }
        };

        let pkcs11_recipients: Vec<KeyType> = add_pub_keys(&decrypt_config_pubkeys, &pubkeys)?;

        if pkcs11_recipients.is_empty() {
            return Ok(Vec::new());
        }

        Ok(encrypt_multiple(&pkcs11_recipients, opts_data)?)
    }

    fn unwrap_keys(&self, dc: &DecryptConfig, annotation: &[u8]) -> Result<Vec<u8>> {
        let mut pkcs11_keys = Vec::new();

        let priv_keys = match self.private_keys(&dc.param) {
            Some(x) => x,
            None => return Err(anyhow!("")),
        };

        let p11conf_opt = p11conf_from_params(&dc.param)?;

        for key in priv_keys {
            let mut k = parse_private_key(&key, &vec![], "PKCS11".to_string())?;
            match k {
                KeyType::rpk(r) => {}
                KeyType::pkfo(mut p) => {
                    if let Some(ref p11conf) = p11conf_opt {
                        p.uriw.set_module_directories(&p11conf.module_directories);
                        p.uriw
                            .set_allowed_module_paths(&p11conf.allowed_module_paths);
                        pkcs11_keys.push(p);
                    }
                }
            }
        }

        Ok(decrypt_pkcs11(&pkcs11_keys, annotation)?)
    }

    fn annotation_id(&self) -> &str {
        "org.opencontainers.image.enc.keys.pkcs11"
    }

    fn no_possible_keys(&self, dcparameters: &HashMap<String, Vec<Vec<u8>>>) -> bool {
        self.private_keys(dcparameters).is_none()
    }

    fn private_keys(&self, dcparameters: &HashMap<String, Vec<Vec<u8>>>) -> Option<Vec<Vec<u8>>> {
        dcparameters.get("pkcs11-yamls").cloned()
    }

    fn recipients(&self, _packet: String) -> Option<Vec<String>> {
        Some(vec!["[pkcs11]".to_string()])
    }
}

fn p11conf_from_params(
    dcparameters: &HashMap<String, Vec<Vec<u8>>>,
) -> Result<Option<Pkcs11Config>> {
    if dcparameters.contains_key("pkcs11-config") {
        return Ok(Some(parse_pkcs11_config_file(
            &dcparameters["pkcs11-config"][0],
        )?));
    }
    Ok(None)
}

fn add_pub_keys(dc: &DecryptConfig, pubkeys: &Vec<Vec<u8>>) -> Result<Vec<KeyType>> {
    let mut pkcs11_keys = Vec::<KeyType>::new();
    if pubkeys.is_empty() {
        return Ok(pkcs11_keys);
    }

    let p11conf_opt = p11conf_from_params(&dc.param)?;

    for pubkey in pubkeys {
        let mut k = parse_public_key(pubkey, "PKCS11".to_string())?;
        match &mut k {
            KeyType::rpk(r) => {}
            KeyType::pkfo(p) => {
                if let Some(ref p11conf) = p11conf_opt {
                    p.uriw.set_module_directories(&p11conf.module_directories);
                    p.uriw
                        .set_allowed_module_paths(&p11conf.allowed_module_paths);
                }
            }
        }
        pkcs11_keys.push(k);
    }

    Ok(pkcs11_keys)
}

#[cfg(test)]
mod kw_tests {
    use super::*;

    //const SOFTHSM_SETUP: &str = "../../scripts/softhsm_setup";

    #[test]
    fn test_keywrap_pkcs11_success() {
        let path_to_script = env!("CARGO_MANIFEST_DIR").to_string() + "/scripts/softhsm_setup";
        let vs = create_valid_pkcs11_ccs().unwrap();
        let valid_pkcs11_ccs = vs.0;
        let shsm = vs.1;

        std::env::set_var("OCICRYPT_OAEP_HASHALG", "sha1");

        for cc in valid_pkcs11_ccs {
            let kw = Pkcs11KeyWrapper {};

            let data = "This is some secret text".as_bytes();

            if let Some(ec) = cc.encrypt_config {
                let wk = kw.wrap_keys(&ec, data).unwrap();
                if let Some(dc) = cc.decrypt_config {
                    let ud = kw.unwrap_keys(&dc, &wk).unwrap();
                    assert_eq!(data, ud);
                } else {
                    assert!(false);
                }
            } else {
                assert!(false);
            }
        }

        shsm.run_softhsm_teardown(&path_to_script);
    }

    #[test]
    fn test_annotation_id() {
        let pkcs11_key_wrapper = Pkcs11KeyWrapper {};
        assert_eq!(
            pkcs11_key_wrapper.annotation_id(),
            "org.opencontainers.image.enc.keys.pkcs11"
        );
    }

    #[test]
    fn test_no_possible_keys() {
        let pkcs11_key_wrapper = Pkcs11KeyWrapper {};
        let dc = DecryptConfig::default();
        assert!(pkcs11_key_wrapper.no_possible_keys(&dc.param));
    }

    #[test]
    fn test_private_keys() {
        let pkcs11_key_wrapper = Pkcs11KeyWrapper {};
        let dc = DecryptConfig::default();
        assert!(pkcs11_key_wrapper.private_keys(&dc.param).is_none());
        // TODO: test positive case (is_some)
    }

    #[test]
    fn test_key_ids_from_packet() {
        let pkcs11_key_wrapper = Pkcs11KeyWrapper {};
        assert!(pkcs11_key_wrapper.keyids_from_packet("".to_string()) == None);
    }

    #[test]
    fn test_recipients() {
        let pkcs11_key_wrapper = Pkcs11KeyWrapper {};
        let recipients = pkcs11_key_wrapper.recipients("".to_string()).unwrap();
        assert!(recipients.len() == 1);
        assert!(recipients[0] == "[pkcs11]");
    }

    fn load_data_path() -> String {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("data");
        path.to_str().unwrap().to_string()
    }

    fn get_pkcs11_config_yaml() -> Result<Vec<u8>> {
        // we need to provide a configuration file so that on the various
        // distros the libsofthsm2.so will be found by searching directories
        let mdyaml = get_default_module_directories_yaml("".to_string())?;
        let config = format!(
            "module_directories:\n\
                              {}\
                              allowed_module_paths:\n\
                              {}",
            mdyaml, mdyaml
        );
        Ok(config.as_bytes().to_vec())
    }

    fn create_valid_pkcs11_ccs() -> Result<(Vec<CryptoConfig>, SoftHSMSetup)> {
        let shsm = SoftHSMSetup::new()?;
        // FIXME: This pathing is brittle. Should we be relative to this module
        // file?  Should it be based off the project's root folder? What about
        // after `make install`?
        let path_to_script = env!("CARGO_MANIFEST_DIR").to_string() + "/scripts/softhsm_setup";
        let pkcs11_pubkey_uri_str = shsm.run_softhsm_setup(&path_to_script)?;
        let pubkey_pem = shsm.run_softhsm_get_pubkey(&path_to_script)?;
        let pkcs11_privkey_yaml = format!(
            "pkcs11:
  uri: {}
module:
  env:
    SOFTHSM2_CONF: {}",
            pkcs11_pubkey_uri_str,
            shsm.get_config_filename()?
        );
        let p11conf_yaml = get_pkcs11_config_yaml()?;

        let mut k1_ec_p = HashMap::new();
        k1_ec_p.insert(
            "pkcs11-pubkeys".to_string(),
            vec![pubkey_pem.as_bytes().to_vec()],
        );
        let mut k1_ec_dc_p = HashMap::new();
        k1_ec_dc_p.insert(
            "pkcs11-yamls".to_string(),
            vec![pkcs11_privkey_yaml.as_bytes().to_vec()],
        );
        k1_ec_dc_p.insert("pkcs11-config".to_string(), vec![p11conf_yaml.to_vec()]);
        let mut k1_dc_p = HashMap::new();
        k1_dc_p.insert(
            "pkcs11-yamls".to_string(),
            vec![pkcs11_privkey_yaml.as_bytes().to_vec()],
        );
        k1_dc_p.insert("pkcs11-config".to_string(), vec![p11conf_yaml.to_vec()]);

        let mut k2_ec_p = HashMap::new();
        // public and private key YAMLs are identical
        k2_ec_p.insert(
            "pkcs11-yamls".to_string(),
            vec![pkcs11_privkey_yaml.as_bytes().to_vec()],
        );
        let mut k2_ec_dc_p = HashMap::new();
        k2_ec_dc_p.insert(
            "pkcs11-yamls".to_string(),
            vec![pkcs11_privkey_yaml.as_bytes().to_vec()],
        );
        k2_ec_dc_p.insert("pkcs11-config".to_string(), vec![p11conf_yaml.to_vec()]);
        let mut k2_dc_p = HashMap::new();
        k2_dc_p.insert(
            "pkcs11-yamls".to_string(),
            vec![pkcs11_privkey_yaml.as_bytes().to_vec()],
        );
        k2_dc_p.insert("pkcs11-config".to_string(), vec![p11conf_yaml.to_vec()]);

        let valid_pkcs11_ccs: Vec<CryptoConfig> = vec![
            // Key 1
            CryptoConfig {
                encrypt_config: Some(EncryptConfig {
                    param: k1_ec_p,
                    decrypt_config: Some(DecryptConfig { param: k1_ec_dc_p }),
                }),
                decrypt_config: Some(DecryptConfig { param: k1_dc_p }),
            },
            // Key 2
            CryptoConfig {
                encrypt_config: Some(EncryptConfig {
                    param: k2_ec_p,
                    decrypt_config: Some(DecryptConfig { param: k2_ec_dc_p }),
                }),
                decrypt_config: Some(DecryptConfig { param: k2_dc_p }),
            },
        ];
        Ok((valid_pkcs11_ccs, shsm))
    }
}
