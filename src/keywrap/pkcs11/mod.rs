use crate::keywrap::KeyWrapper;
use crate::config::EncryptConfig;
use crate::config::DecryptConfig;
use std::collections::HashMap;
use pkcs11_uri::{Pkcs11Uri};
use crate::utils::{parse_pkcs11_key_file, encrypt_multiple, decrypt_pkcs11};
use crate::ors_error::OrsError;

#[derive(Debug)]
pub struct Pkcs11KeyWrapper {}

// Pkcs11KeyFileObject is a representation of the Pkcs11KeyFile with the pkcs11
// URI as an object
pub struct Pkcs11KeyFileObject {
    pub uri: Pkcs11Uri,
    // A map of environment variables needed by the pkcs11 module using this URI.
    pub env: HashMap<String, String>,
}


// Pkcs11Config describes the layout of a pkcs11 config file
// The file has the following yaml format:
// module_directories:
// - /usr/lib64/pkcs11/
// allowed_module_paths
// - /usr/lib64/pkcs11/libsofthsm2.so
struct Pkcs11Config {
    module_directories: Vec<String>,
    allowed_module_paths: Vec<String>,
}

impl KeyWrapper for Pkcs11KeyWrapper {
    
    // wrap_keys wraps the session key for recpients and encrypts the opts_data,
    // which describe the symmetric key used for encrypting the layer
    fn wrap_keys(&self,
                 ec: &EncryptConfig,
                 opts_data: &Vec<u8>)
                 -> Result<Vec<u8>, OrsError> {
        let mut x: Vec<Vec<u8>> = Vec::new();
        let ps: &Vec<Vec<u8>> = &ec.param["pkcs11-pubkeys"];
        for p in ps {
            x.push(p.to_vec());
        }
        for y in &ec.param["pkcs11-yamls"] {
            x.push(y.to_vec());
        }
        let dc = match ec.decrypt_config.as_ref() {
            Some(x) => x,
            None => return Err(OrsError::TODOGeneral),
        };

        let pkcs11_recipients: Vec<Pkcs11KeyFileObject>
          = add_pub_keys(&dc, &x)?;

        if pkcs11_recipients.is_empty() {
            return Ok(Vec::new())
        }

        let json_str = encrypt_multiple(&pkcs11_recipients, opts_data)?;

        Ok(json_str)
    }

    fn unwrap_key(&self,
                  dc: &DecryptConfig,
                  annotation: &Vec<u8>)
                  -> Result<Vec<u8>, OrsError> {

        let mut pkcs11_keys = Vec::new();

        let priv_keys = match self.private_keys(&dc.param) {
            Some(x) => x,
            None => return Err(OrsError::TODOGeneral),
        };

        let p11_conf = p11_conf_from_params(&dc.param)?;

        for k in priv_keys {

            let key: Pkcs11KeyFileObject = parse_pkcs11_key_file(&k)?;
            // FIXME: Do we need more fields for the key here?
            //key.uri.SetModuleDirectories(p11conf.ModuleDirectories)
            //key.uri.SetAllowedModulePaths(p11conf.AllowedModulePaths)
            pkcs11_keys.push(key);
        }

        let plaintext = decrypt_pkcs11(&pkcs11_keys, annotation)?;

        Ok(plaintext)
    }


    fn annotation_id(&self) -> &str {
        "org.opencontainers.image.enc.keys.pkcs11"
    }

    fn no_possible_keys(&self,
                        dcparameters: &HashMap<String, Vec<Vec<u8>>>)
                        -> bool {
        self.private_keys(dcparameters).is_none()
    }

    fn private_keys(&self,
                    dcparameters: &HashMap<String, Vec<Vec<u8>>>)
                    -> Option<Vec<Vec<u8>>> {
        dcparameters.get("pkcs11-yamls").cloned()
    }

    fn key_ids_from_packet(&self,
                           _: String)
                           -> Result<Vec<u64>, std::io::Error> {
        // FIXME return nil, nil
        Ok(Vec::new())
    }


    fn recipients(&self,
                  _packet: String)
                  -> Result<Vec<String>, std::io::Error> {
        Ok(vec!["[pkcs11]".to_string()])
    }
}


fn p11_conf_from_params(dcparameters: &HashMap<String, Vec<Vec<u8>>>)
                        -> Result<Pkcs11Config, OrsError> {
    // FIXME: c is just a placeholder for now
    let c = Pkcs11Config{
        module_directories: Vec::default(),
        allowed_module_paths: Vec::default(),
    };
    if dcparameters.contains_key("pkcs11-config") {
        // TODO
        //return pkcs11.ParsePkcs11ConfigFile(dcparameters["pkcs11-config"][0])
        return Ok(c);
    }
    // FIXME was "nil, nil" in golang. Should probably be Option here
    Ok(c)
}

fn add_pub_keys(dc: &DecryptConfig,
                pub_keys: &Vec<Vec<u8>>)
                -> Result<Vec<Pkcs11KeyFileObject>, OrsError> {
    let mut pkcs11_keys = Vec::new();
    if pub_keys.is_empty() {
        return Ok(pkcs11_keys);
    }

    let p11_conf = p11_conf_from_params(&dc.param)?;

    for k in pub_keys {
            let key: Pkcs11KeyFileObject = parse_pkcs11_key_file(k)?;
            // FIXME: Do we need more fields for the key here?
            //key.uri.SetModuleDirectories(p11conf.ModuleDirectories);
            //key.uri.SetAllowedModulePaths(p11conf.AllowedModulePaths);
            pkcs11_keys.push(key);
    }

    Ok(pkcs11_keys)
}




#[cfg(test)]
mod kw_tests {
    use super::*;

    #[test]
    fn test_annotation_id() {
        let pkcs11_key_wrapper = Pkcs11KeyWrapper{};
        assert_eq!(pkcs11_key_wrapper.annotation_id(),
                   "org.opencontainers.image.enc.keys.pkcs11");
    }

    #[test]
    fn test_no_possible_keys() {
        let pkcs11_key_wrapper = Pkcs11KeyWrapper{};
        let mut dc = DecryptConfig::default();
        assert!(pkcs11_key_wrapper.no_possible_keys(&dc.param));
    }

    #[test]
    fn test_recipients() {
        let pkcs11_key_wrapper = Pkcs11KeyWrapper{};
        let recipients = pkcs11_key_wrapper.recipients("".to_string()).unwrap();
        assert!(recipients.len() == 1);
        assert!(recipients[0] == "[pkcs11]");
    }
}
