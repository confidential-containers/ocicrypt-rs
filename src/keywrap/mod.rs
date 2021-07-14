pub mod pkcs11;

use crate::config::EncryptConfig;
use crate::config::DecryptConfig;
use std::collections::HashMap;
use crate::ors_error::OrsError;

trait KeyWrapper {
    fn wrap_keys(&self,
                 ec: &EncryptConfig,
                 opts_data: &Vec<u8>)
                 -> Result<Vec<u8>, OrsError>;

    fn unwrap_key(&self,
                  cfg: &DecryptConfig,
                  annotation: &Vec<u8>)
                  -> Result<Vec<u8>, OrsError>;

    fn annotation_id(&self) -> &str;

    fn no_possible_keys(&self,
                        dcparameters: &HashMap<String, Vec<Vec<u8>>>)
                        -> bool;

    fn private_keys<'a>(&'a self,
                        dcparameters: &'a HashMap<String, Vec<Vec<u8>>>)
                        -> &'a Vec<Vec<u8>>;

    fn key_ids_from_packet(&self,
                           packet: String)
                           -> Result<Vec<u64>, std::io::Error>;

    fn recipients(&self,
                  packet: String)
                  -> Result<Vec<String>, std::io::Error>;
}
