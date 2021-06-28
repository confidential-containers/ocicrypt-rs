use std::collections::HashMap;
use pkcs11_uri::{Pkcs11Uri};
use crate::keywrap::pkcs11::Pkcs11KeyFileObject;

extern crate serde_yaml;
extern crate base64;

// OAEPDefaultHash defines the default hash used for OAEP encryption; this
// cannot be changed
static OAEP_DEFAULT_HASH: &str = "sha1";



// Pkcs11KeyFile describes the format of the pkcs11 (private) key file.
// It also carries pkcs11 module related environment variables that are
// transferred to the Pkcs11URI object and activated when the pkcs11 module is
// used.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Pkcs11KeyFile {
    uri: String,
    env: HashMap<String, String>,
}


// Pkcs11Blob holds the encrypted blobs for all recipients; this is what we will put into the image's annotations
#[derive(Serialize, Deserialize)]
struct Pkcs11Blob {
    version:    u32,              //`json:"version"`
    recipients: Vec<Pkcs11Recipient>, // `json:"recipients"`
}

// Pkcs11Recipient holds the b64-encoded and encrypted blob for a particular
// recipient
#[derive(Serialize, Deserialize)]
struct Pkcs11Recipient {
    version: u32, //`json:"version"`
    blob:    String, // `json:"blob"`
    hash:    String, // `json:"hash,omitempty"`
}


pub fn parse_pkcs11_uri(uri: &str) -> Result<Pkcs11Uri, std::io::Error> {
    Ok(Pkcs11Uri::try_from(uri).unwrap())
}


// ParsePkcs11KeyFile parses a pkcs11 key file holding a pkcs11 URI describing
// a private key.
// The file has the following yaml format:
// pkcs11:
//  - uri : <pkcs11 uri>                                                                  // An error is returned if the pkcs11 URI is malformed
pub fn parse_pkcs11_key_file(yaml_bytes: &Vec<u8>)
                             -> Result<Pkcs11KeyFileObject, std::io::Error> {
    let s = serde_yaml::to_string(yaml_bytes).unwrap();
    let p11_key_file: Pkcs11KeyFile = serde_yaml::from_str(&s).unwrap(); 

    let p11_uri = parse_pkcs11_uri(&p11_key_file.uri).unwrap();

    // TODO ?
    // some equivalent to this golang code:
    //   p11_uri.SetEnvMap(p11keyfile.Module.Env)
    // but it's "only there for convenience"
    // https://github.com/stefanberger/go-pkcs11uri/blob/master/pkcs11uri.go#L43-L45
    // We could wrap the Pkcs11Uri object and add the env if needed.

    let kfo = Pkcs11KeyFileObject {
        uri: p11_uri,
    };
    Ok(kfo)
}




fn public_encrypt_oaep(pubKey: &Pkcs11KeyFileObject,
                       plaintext: &Vec<u8>)
                       -> Result<(Vec<u8>, String), std::io::Error> {
    // TODO
    Ok((Vec::new(), "".to_string()))
}




// EncryptMultiple encrypts for one or multiple pkcs11 devices; the public keys passed to this function
// may either be *rsa.PublicKey or *pkcs11uri.Pkcs11URI; the returned byte array is a JSON string of the
// following format:
// {
//   recipients: [  // recipient list
//     {
//        "version": 0,
//        "blob": <base64 encoded RSA OAEP encrypted blob>,
//        "hash": <hash used for OAEP other than 'sha256'>
//     } ,
//     {
//        "version": 0,
//        "blob": <base64 encoded RSA OAEP encrypted blob>,
//        "hash": <hash used for OAEP other than 'sha256'>
//     } ,
//     [...]
//   ]
// }
pub fn encrypt_multiple(pub_keys: &Vec<Pkcs11KeyFileObject>,
                       data: &Vec<u8>)
                       -> Result<Vec<u8>, std::io::Error> {

    let mut pkcs11_blob: Pkcs11Blob = Pkcs11Blob{
        version: 0,
        recipients: Vec::new(),
    };
    for pub_key in pub_keys {
        let ciphertext_hashalg = public_encrypt_oaep(pub_key, data).unwrap();
        let ciphertext = ciphertext_hashalg.0;
        let mut hashalg = ciphertext_hashalg.1;

        if hashalg == OAEP_DEFAULT_HASH {
            hashalg = "".to_string();
        }
        let recipient = Pkcs11Recipient {
            version: 0,
            blob:    base64::encode(ciphertext),
            hash:    hashalg,
        };

        pkcs11_blob.recipients.push(recipient);
    }
    Ok(serde_json::to_vec(&pkcs11_blob).unwrap())
}
