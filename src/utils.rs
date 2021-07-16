use std::collections::HashMap;
use pkcs11_uri::{Pkcs11Uri};
use crate::keywrap::pkcs11::Pkcs11KeyFileObject;
use http::Uri;
use crate::ors_error::OrsError;


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


pub fn parse_pkcs11_uri(uri: &str) -> Result<Pkcs11Uri, OrsError> {
    let x = Pkcs11Uri::try_from(uri)?;
    Ok(x)
}


// ParsePkcs11KeyFile parses a pkcs11 key file holding a pkcs11 URI describing
// a private key.
// The file has the following yaml format:
// pkcs11:
//  - uri : <pkcs11 uri>                                                                  // An error is returned if the pkcs11 URI is malformed
pub fn parse_pkcs11_key_file(yaml_bytes: &Vec<u8>)
                             -> Result<Pkcs11KeyFileObject, OrsError> {
    let s = serde_yaml::to_string(yaml_bytes)?;
    let p11_key_file: Pkcs11KeyFile = serde_yaml::from_str(&s)?;

    let p11_uri = parse_pkcs11_uri(&p11_key_file.uri)?;

    Ok(Pkcs11KeyFileObject {
        uri: p11_uri,
        env: p11_key_file.env,
    })
}


// setEnvVars sets the environment variables given in the map and locks the
// environment from modification with the same function; if successful, you
// *must* call restoreEnv with the return
// value from this function
fn set_env_vars(env: &HashMap<String, String>)
                -> Option<std::env::Vars> {
    // TODO lock
    if env.is_empty() {
        return None;
    }
    let oldenv = std::env::vars();
    for (key, value) in std::env::vars() {
        std::env::set_var(key, value);
        // FIXME ? is there no way to check set-var's return code?
    }
    Some(oldenv)
}

// pkcs11_open_session opens a session with a pkcs11 device at the given slot
// and logs in with the given PIN
fn pkcs11_open_session(p11ctx: &pkcs11::Ctx,
                       slotid: u64,
                       pin: String)
                       -> Result<pkcs11::types::CK_SESSION_HANDLE, OrsError> {
    let flags = pkcs11::types::CKF_SERIAL_SESSION | pkcs11::types::CKF_RW_SESSION;
    let session =
      p11ctx.open_session(slotid,
                          flags,
                          None,
                          None)?;
    if !pin.is_empty() {
        // TODO
        let usertype = 0;
        let _ = p11ctx.login(session, usertype, None /*pin*/);
    }
    Ok(1)
}

// HasPIN allows the user to check whether a PIN has been provided either by the pin-value or the pin-source
// attributes. It should be called before GetPIN(), which may still fail getting the PIN from a file for example.
fn has_pin(p11uri: &Pkcs11Uri) -> bool {
    match &p11uri.query_attributes.pin_value {
        Some(_x) => return true,
        None => {},
    }
    match &p11uri.query_attributes.pin_source {
        Some(_x) => return true,
        None => {},
    }
    false
}

// GetPIN gets the PIN from either the pin-value or pin-source attribute; a user may want to call HasPIN()
// before calling this function to determine whether a PIN has been provided at all so that an error code
// returned by this function indicates that the PIN value could not be retrieved.
fn pin(p11uri: &Pkcs11Uri) -> Result<String, OrsError> {
    match &p11uri.query_attributes.pin_value {
        Some(x) => return Ok(x.to_string()),
        None => {},
    }
    match &p11uri.query_attributes.pin_source {
        Some(v) => {
            let pinuri = &v.parse::<Uri>()?;
            let p = match pinuri.scheme_str() {
                Some(x) => x,
                None => return Err(OrsError::TODOGeneral),
            };
            match p {
                "" | "file" => {
                    if !std::path::Path::new(pinuri.path()).is_absolute() {
                        // TODO error
                    }
                    let pin = std::fs::read_to_string(pinuri.path())?;
                    return Ok(pin)
                },
                _ => {},
                // FIXME error
                //return "", fmt.Errorf("PIN URI scheme %s is not supported", pinuri.Scheme)
            }
        },
        None => {},
    }
    // FIXME error
    Ok("".to_string())
}

fn module(p11uri: &Pkcs11Uri) -> Result<&String, OrsError> {
    // FIXME this is not correct. see golang pkcs11-uri. need to search
    // directories
    match p11uri.query_attributes.module_name.as_ref() {
        Some(x) => Ok(x),
        None => Err(OrsError::TODOGeneral),
    }
}


// pkcs11_uri_get_login_parameters gets the parameters necessary for login from the
// Pkcs11URI PIN and module are mandatory; slot-id is optional and if not found
// -1 will be returned For a private_key_operation a PIN is required and if none
// is given, this function will return an error
fn pkcs11_uri_get_login_parameters(p11uri: &Pkcs11Uri,
                                   private_key_operation: bool)
                                   -> Result<(String, &String, Option<u64>), OrsError> {

    if private_key_operation {
        if !has_pin(p11uri) {
            return Err(OrsError::TODOGeneral);
        }
    }
    // some devices require a PIN to find a *public* key object, others don't
    let pin = pin(p11uri)?;

    let module_name = module(p11uri)?;

    //let slotid = match p11uri.path_attributes.slot_id {
        //Some(x) => x,
        //None => return None,
    //};
    let slotid = p11uri.path_attributes.slot_id;


    Ok((pin, module_name, slotid))

}

// pkcs11_uri_get_key_id_and_label gets the key label by retrieving the value
// of the 'object' attribute
fn pkcs11_uri_get_key_id_and_label(p11uri: &Pkcs11Uri)
                                   -> Result<(&Vec<u8>, &String), OrsError> {

    let object_id = match p11uri.path_attributes.object_id.as_ref() {
        Some(x) => x,
        None => return Err(OrsError::TODOGeneral),
    };
    let object_label = match p11uri.path_attributes.object_label.as_ref() {
        Some(x) => x,
        None => return Err(OrsError::TODOGeneral),
    };
    Ok((object_id, object_label))
}


// pkcs11UriLogin uses the given pkcs11 URI to select the pkcs11 module (share
// libary) and to get the PIN to use for login; if the URI contains a slot-id,
// the given slot-id will be used, otherwise one slot after the other will be
// attempted and the first one where login succeeds will be used
fn pkcs11_uri_login(p11uri: &Pkcs11Uri,
                    private_key_operation: bool)
                    -> Result<(pkcs11::Ctx, pkcs11::types::CK_SESSION_HANDLE),
                               OrsError> {
    let pin_module_slotid
      = pkcs11_uri_get_login_parameters(p11uri, private_key_operation)?;
    let pin = pin_module_slotid.0;
    let module = pin_module_slotid.1;
    let slotid = pin_module_slotid.2;

    let mut p11ctx = pkcs11::Ctx::new(module)?;
    let session = 64;

    let _ = p11ctx.initialize(None);

    // FIXME: This should not be a >= 0 check. slotid will always be unsigned
    // with rust pkcs11 uri. This should instead be an error check on
    // pkcs11-uri-get-login-parameters.
    match slotid {
        Some(sid) => {
            if sid > 0xffffffff {
                return Err(OrsError::TODOGeneral);
            }
            let session = pkcs11_open_session(&p11ctx, sid, pin)?;
            return Ok((p11ctx, session))
        },
        None => {
            let slots = p11ctx.get_slot_list(true)?;

            let tokenlabel = match p11uri.path_attributes.token_label.as_ref() {
                Some(x) => x,
                None => return Err(OrsError::TODOGeneral),
            };

            for slot in slots {
                //let ti = p11ctx.get_token_info(slot)?;
                let ti = match p11ctx.get_token_info(slot) {
                    Ok(o) => o,
                    Err(_) => return Err(OrsError::TODOGeneral),
                };
                if &String::from(ti.label) != tokenlabel {
                    continue;
                }

                let session = pkcs11_open_session(&p11ctx, slot, pin)?;
                return Ok((p11ctx, session))
            }
            // TODO: handle error cases
            /*if len(pin) > 0 {
                return nil, 0, errors.New("Could not create session to any slot and/or log in")
            }
            return nil, 0, errors.New("Could not create session to any slot")*/
            Ok((p11ctx, session))
        }
    }

}

// find_object finds an object of the given class with the given object_id and/or
// object_label
fn find_object(p11ctx: &pkcs11::Ctx,
               session: pkcs11::types::CK_SESSION_HANDLE,
               class: u64,
               object_id: &Vec<u8>,
               object_label: &String)
               -> Result<pkcs11::types::CK_OBJECT_HANDLE, OrsError> {
    let mut msg = "".to_string();

    let mut template = Vec::new();
    let mut a = pkcs11::types::CK_ATTRIBUTE::new(pkcs11::types::CKA_CLASS);
    a.set_ck_ulong(&class);
    template.push(a);

    if !object_label.is_empty() {
        let mut b = pkcs11::types::CK_ATTRIBUTE::new(pkcs11::types::CKA_LABEL);
        b.set_string(object_label);
        template.push(b);
        // FIXME surely this & format() to-string() is wrong
        msg += &format!("object_label '{}'", object_label).to_string();
    }
    if !object_id.is_empty() {
        let mut c = pkcs11::types::CK_ATTRIBUTE::new(pkcs11::types::CKA_ID);
        c.set_bytes(object_id);
        template.push(c);
        if !msg.is_empty() {
            msg += " and "
        }
        // TODO rust pathescape?
        //msg += url.PathEscape(object_id)
    }

    let _ = p11ctx.find_objects_init(session, &template);

    let obj_handles = p11ctx.find_objects(session, 100)?;

    let _ = p11ctx.find_objects_final(session);

    if obj_handles.len() > 1 {
        // TODO error
    } else if obj_handles.len() == 1 {
        return Ok(obj_handles[0]);
    }
    // TODO error
    Ok(0)
}

fn oaep_hashalg(oaephash: String)
                -> Result<(pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS, String), OrsError> {
    // TODO can we move initialize these Params variables once?
    // Thread safety issue in rust when naively trying to make it static-global
    // See also oaep()

    // OAEPLabel defines the label we use for OAEP encryption; this cannot be changed
    // TODO
    let OAEPLabel: *mut pkcs11::types::CK_VOID = std::ptr::null_mut();
    let label_len: pkcs11::types::CK_ULONG = 0;

    // Oaep_Sha1_Params describes the OAEP parameters with sha1 hash algorithm;
    // needed by SoftHSM
    let Oaep_Sha1_Params: pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS
      = pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: pkcs11::types::CKM_SHA1_RSA_PKCS,
        mgf: pkcs11::types::CKG_MGF1_SHA1,
        source: pkcs11::types::CKZ_DATA_SPECIFIED,
        pSourceData: OAEPLabel,
        ulSourceDataLen: label_len,
    };


    // Oaep_Sha256_Params describes the OAEP parameters with sha256 hash
    // algorithm
    let Oaep_Sha256_Params: pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS
      = pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: pkcs11::types::CKM_SHA256_RSA_PKCS,
        mgf: pkcs11::types::CKG_MGF1_SHA256,
        source: pkcs11::types::CKZ_DATA_SPECIFIED,
        pSourceData: OAEPLabel,
        ulSourceDataLen: label_len,
    };

    let tmp = match oaephash.to_lowercase().as_str() {
        "" => (Oaep_Sha1_Params, "sha1".to_string()),
        "sha1" => (Oaep_Sha1_Params, "sha1".to_string()),
        "sha256" => (Oaep_Sha256_Params, "sha256".to_string()),
        // FIXME: _ case should return nil and error
        _ => (Oaep_Sha256_Params, "sha256".to_string()),
    };
    Ok(tmp)
}
fn oaep(hashalg: &String) -> Result<pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS,
                                    OrsError> {

    // TODO: See oaep_hashalg
    let OAEPLabel: *mut pkcs11::types::CK_VOID = std::ptr::null_mut();
    let label_len: pkcs11::types::CK_ULONG = 0;

    // Oaep_Sha1_Params describes the OAEP parameters with sha1 hash algorithm;
    // needed by SoftHSM
    let Oaep_Sha1_Params: pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS
      = pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: pkcs11::types::CKM_SHA1_RSA_PKCS,
        mgf: pkcs11::types::CKG_MGF1_SHA1,
        source: pkcs11::types::CKZ_DATA_SPECIFIED,
        pSourceData: OAEPLabel,
        ulSourceDataLen: label_len,
    };
    // Oaep_Sha256_Params describes the OAEP parameters with sha256 hash
    // algorithm
    let Oaep_Sha256_Params: pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS
      = pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS {
        hashAlg: pkcs11::types::CKM_SHA256_RSA_PKCS,
        mgf: pkcs11::types::CKG_MGF1_SHA256,
        source: pkcs11::types::CKZ_DATA_SPECIFIED,
        pSourceData: OAEPLabel,
        ulSourceDataLen: label_len,
    };

    let oaep = match hashalg.to_lowercase().as_str() {
        "sha1" | "" => Oaep_Sha1_Params,
        "sha256" => Oaep_Sha256_Params,
        // FIXME: _ case should error
        _ => Oaep_Sha256_Params,
    };
    Ok(oaep)
}


// publicEncryptOAEP uses a public key described by a pkcs11 URI to OAEP
// encrypt the given plaintext
fn public_encrypt_oaep(pub_key: &Pkcs11KeyFileObject,
                       plaintext: &[u8])
                       -> Result<(Vec<u8>, String), OrsError> {
    // TODO
    // defer restoreEnv(oldenv)
    // defer pkcs11Logout(p11ctx, session)

    let oldenv = set_env_vars(&pub_key.env);

    let p11ctx_session = pkcs11_uri_login(&pub_key.uri, false)?;
    let p11ctx = p11ctx_session.0;
    let session = p11ctx_session.1;

    let object_id_label = pkcs11_uri_get_key_id_and_label(&pub_key.uri)?;
    let object_id = object_id_label.0;
    let object_label = object_id_label.1;

    let p11_pub_key = find_object(&p11ctx,
                                  session,
                                  pkcs11::types::CKO_PUBLIC_KEY,
                                  object_id,
                                  object_label)?;

    let oaephash = match std::env::var("OCICRYPT_OAEP_HASHALG") {
        Ok(x) => x,
        Err(_) => return Err(OrsError::TODOGeneral),
    };

    let oaep_hashalg = oaep_hashalg(oaephash)?;

    let mut oaep = oaep_hashalg.0;
    let hashalg = oaep_hashalg.1;

    let oaep_p: *mut pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS = &mut oaep;

    let mech = pkcs11::types::CK_MECHANISM {
        mechanism: pkcs11::types::CKM_RSA_PKCS_OAEP,
        // FIXME this can't be right
        pParameter: oaep_p as *mut pkcs11::types::CK_VOID,
        // FIXME: This should be something like "oaep.len()", but oaep is of
        // type CK_RSA_PKCS_OAEP_PARAMS. Do we want the size of the struct
        // here?  (Alternatively, do we want the size of pSourceData, i.e.
        // ulSourceDataLen, or something else?)
        ulParameterLen: 0,
    };
    let _ = p11ctx.encrypt_init(session, &mech, p11_pub_key)?;

    let ciphertext = p11ctx.encrypt(session, plaintext)?;

    Ok((ciphertext, hashalg))
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
                       data: &[u8])
                       -> Result<Vec<u8>, OrsError> {

    let mut pkcs11_blob: Pkcs11Blob = Pkcs11Blob{
        version: 0,
        recipients: Vec::new(),
    };
    for pub_key in pub_keys {
        let ciphertext_hashalg = public_encrypt_oaep(pub_key, data)?;
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
    Ok(serde_json::to_vec(&pkcs11_blob)?)
}

// privateDecryptOAEP uses a pkcs11 URI describing a private key to OAEP decrypt a ciphertext
//func privateDecryptOAEP(privKeyObj *Pkcs11KeyFileObject, ciphertext []byte, hashalg string) ([]byte, error) {
fn private_decrypt_oaep(priv_key: &Pkcs11KeyFileObject,
                        ciphertext: &Vec<u8>,
                        hashalg: &String)
                        -> Result<Vec<u8>, OrsError> {
    // FIXME remove boilerplate similar to public_encrypt_oaep
    // TODO
    // defer restoreEnv(oldenv)
    // defer pkcs11Logout(p11ctx, session)
    let oldenv = set_env_vars(&priv_key.env);

    let p11ctx_session = pkcs11_uri_login(&priv_key.uri, true)?;
    let p11ctx = p11ctx_session.0;
    let session = p11ctx_session.1;

    let object_id_label = pkcs11_uri_get_key_id_and_label(&priv_key.uri)?;
    let object_id = object_id_label.0;
    let object_label = object_id_label.1;

    let p11_priv_key = find_object(&p11ctx,
                                  session,
                                  pkcs11::types::CKO_PRIVATE_KEY,
                                  object_id,
                                  object_label)?;

    let mut oaep = oaep(hashalg)?;

    // FIXME: boilerplate similar to encrypt_init
    let oaep_p: *mut pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS = &mut oaep;
    let mech = pkcs11::types::CK_MECHANISM {
        mechanism: pkcs11::types::CKM_RSA_PKCS_OAEP,
        // FIXME this can't be right
        pParameter: oaep_p as *mut pkcs11::types::CK_VOID,
        // FIXME: This should be something like "oaep.len()", but oaep is of
        // type CK_RSA_PKCS_OAEP_PARAMS. Do we want the size of the struct
        // here?  (Alternatively, do we want the size of pSourceData, i.e.
        // ulSourceDataLen, or something else?)
        ulParameterLen: 0,
    };
    let _ = p11ctx.decrypt_init(session, &mech, p11_priv_key)?;

    let plaintext = p11ctx.decrypt(session, &ciphertext)?;

    Ok(plaintext)
}


// Decrypt tries to decrypt one of the recipients' blobs using a pkcs11 private key.
// The input pkcs11blobstr is a string with the following format:
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
// }
//func Decrypt(privKeyObjs []*Pkcs11KeyFileObject, pkcs11blobstr []byte) ([]byte, error) {
pub fn decrypt_pkcs11(priv_keys: &Vec<Pkcs11KeyFileObject>,
                      pkcs11blobstr: &[u8])
                      -> Result<Vec<u8>, OrsError> {

    let pkcs11_blob: Pkcs11Blob = serde_json::from_slice(pkcs11blobstr)?;
    if pkcs11_blob.version != 0 {
        return Err(OrsError::TODOGeneral);
    }
    // since we do trial and error, collect all encountered errors
    let mut errs = String::from("");

    for recipient in pkcs11_blob.recipients {
        if recipient.version != 0 {
            return Err(OrsError::TODOGeneral);
        }

        //ciphertext, err := base64.StdEncoding.DecodeString(recipient.Blob)
        let ciphertext = match base64::decode(recipient.blob) {
            Ok(c) => {
                if c.is_empty() {
                    // FIXME append error message of e
                    //"Base64 decoding failed: %s\n", err
                    errs += "1";
                    continue;
                }
                c
            }
            Err(_) => {
                // FIXME append error message of e
                //"Base64 decoding failed: %s\n", err
                errs += "1";
                continue;
            },
        };
        // try all keys until one works
        for priv_key in priv_keys {
            let plaintext = private_decrypt_oaep(priv_key, &ciphertext, &recipient.hash);
            match plaintext {
                Ok(x) => return Ok(x),
                Err(_) => {
                    // TODO
                    //if uri, err2 := privKeyObj.Uri.Format(); err2 == nil {
                    //    errs += fmt.Sprintf("%s : %s\n", uri, err)
                    //} else {
                    //    errs += fmt.Sprintf("%s\n", err)
                    //}
                }
            }
        }
    }

    // TODO use errs string
    //return nil, errors.Errorf("Could not find a pkcs11 key for decryption:\n%s", errs)
    Err(OrsError::TODOGeneral)
}

