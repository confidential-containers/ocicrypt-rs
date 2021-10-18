// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use crate::keywrap::pkcs11::Pkcs11KeyFileObject;
use crate::pkcs11_uri_wrapped::Pkcs11UriWrapped;
use anyhow::{anyhow, Result};
use pkcs11_uri::Pkcs11Uri;
use rand::rngs::OsRng;
use rsa::{pkcs8::FromPublicKey, PaddingScheme, PublicKey, RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;
use std::cmp::Ordering;
use std::collections::HashMap;

extern crate base64;
extern crate serde_yaml;

/// OAEPDefaultHash defines the default hash used for OAEP encryption; this
/// cannot be changed
pub static OAEP_DEFAULT_HASH: &str = "sha1";

/// Pkcs11KeyFile describes the format of the pkcs11 (private) key file.
/// It also carries pkcs11 module-related environment variables that are
/// transferred to the Pkcs11URI object and activated when the pkcs11 module is
/// used.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Pkcs11KeyFile {
    pkcs11: Pkcs11KeyFilePkcs11,
    module: Pkcs11KeyFileModule,
}
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Pkcs11KeyFilePkcs11 {
    uri: String,
}
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Pkcs11KeyFileModule {
    env: HashMap<String, String>,
}

pub enum Pkcs11KeyType {
    RPK(RsaPublicKey),
    PKFO(Box<Pkcs11KeyFileObject>),
}

/// A Pkcs11Blob holds the encrypted blobs for all recipients.
/// This is what we will put into the image's annotations
#[derive(Serialize, Deserialize)]
struct Pkcs11Blob {
    version: u32,
    recipients: Vec<Pkcs11Recipient>,
}

/// A Pkcs11Recipient holds the b64-encoded and encrypted blob for a particular
/// recipient
#[derive(Serialize, Deserialize)]
struct Pkcs11Recipient {
    version: u32,
    blob: String,
    hash: String,
}

pub fn parse_pkcs11_uri(uri: &str) -> Result<Pkcs11Uri> {
    let x = Pkcs11Uri::try_from(uri)?;
    Ok(x)
}

/// Parse a pkcs11 key file holding a pkcs11 URI describing a private key.
/// The file has the following yaml format:
/// pkcs11:
///  - uri : <pkcs11 uri>
/// An error is returned if the pkcs11 URI is malformed.
pub fn parse_pkcs11_key_file(yaml_bytes: &[u8]) -> Result<Pkcs11KeyFileObject> {
    let p11_key_file: Pkcs11KeyFile = serde_yaml::from_slice(yaml_bytes)?;
    let p11_uri = parse_pkcs11_uri(&p11_key_file.pkcs11.uri)?;
    let mut p11uriw = Pkcs11UriWrapped::new(p11_uri);
    p11uriw.set_env_map(p11_key_file.module.env);
    Ok(Pkcs11KeyFileObject { uriw: p11uriw })
}

/// Parse the input byte array as a pkcs11 key file yaml.
fn parse_pkcs11_public_key_yaml(yaml: &[u8], _prefix: String) -> Result<Pkcs11KeyFileObject> {
    // if the URI does not have enough attributes, we will throw an error when
    // decrypting
    parse_pkcs11_key_file(yaml)
}

/// Parse the input byte array as pkcs11 key file (yaml format).
fn parse_pkcs11_private_key_yaml(yaml: &[u8], _prefix: String) -> Result<Pkcs11KeyFileObject> {
    // if the URI does not have enough attributes, we will throw an error when
    // decrypting
    parse_pkcs11_key_file(yaml)
}

/// Try to parse a public key in DER format first and PEM format after,
/// returning an error if the parsing failed.
pub fn parse_public_key(pubkey: &[u8], prefix: String) -> Result<Pkcs11KeyType> {
    // FIXME: handle x509.ParsePKIXPublicKey(pubKey)
    //               x509.ParsePKIXPublicKey(block.Bytes)
    //               parseJWKPublicKey(pubKey, prefix)
    let res: Pkcs11KeyType;
    let a = RsaPublicKey::from_public_key_pem(&String::from_utf8_lossy(pubkey));
    match a {
        Ok(o) => {
            res = Pkcs11KeyType::RPK(o);
        }
        Err(_e) => {
            let key = parse_pkcs11_public_key_yaml(pubkey, prefix);
            match key {
                Ok(k) => {
                    res = Pkcs11KeyType::PKFO(Box::new(k));
                }
                Err(e) => {
                    return Err(anyhow!("parsing pkcs11 yaml failed: {}", e));
                }
            }
        }
    }
    Ok(res)
}

/// Attempt to parse a private key in DER format first and PEM format after,
/// returning an error if the parsing failed.
pub fn parse_private_key(
    privkey: &[u8],
    _privkey_password: &[u8],
    prefix: String,
) -> Result<Pkcs11KeyType> {
    // FIXME: handle key types other than just pkcs11.
    let res: Pkcs11KeyType;
    let key = parse_pkcs11_private_key_yaml(privkey, prefix);
    match key {
        Ok(k) => {
            res = Pkcs11KeyType::PKFO(Box::new(k));
        }
        Err(e) => {
            return Err(anyhow!("parsing pkcs11 yaml failed: {}", e));
        }
    }
    Ok(res)
}

/// Set the environment variables given in the map, and lock the environment
/// from modification with the same function. If successful, you *must* call
/// restoreEnv with the return value from this function
fn set_env_vars(env: &HashMap<String, String>) -> Option<std::env::Vars> {
    // TODO lock
    if env.is_empty() {
        return None;
    }
    let oldenv = std::env::vars();
    for (key, value) in env {
        std::env::set_var(key, value);
    }
    Some(oldenv)
}

/// Open a session with a pkcs11 device at the given slot and log in with the
/// given PIN.
fn pkcs11_open_session(
    p11ctx: &pkcs11::Ctx,
    slotid: u64,
    pin: String,
) -> Result<pkcs11::types::CK_SESSION_HANDLE> {
    let flags = pkcs11::types::CKF_SERIAL_SESSION | pkcs11::types::CKF_RW_SESSION;
    let session = p11ctx.open_session(slotid, flags, None, None)?;
    if !pin.is_empty()
        && p11ctx
            .login(session, pkcs11::types::CKU_USER, Some(&pin))
            .is_err()
    {
        if p11ctx.close_session(session).is_err() {
            return Err(anyhow!("Failed to close session"));
        }
        return Err(anyhow!("Could not log in to device"));
    }
    Ok(session)
}

/// Get the parameters necessary for login from the Pkcs11URI.
/// PIN and module are mandatory; slot-id is optional.
/// For a private_key_operation, a PIN is required, and if none is given, this
/// function will return an error.
fn pkcs11_uri_get_login_parameters(
    p11uriw: &Pkcs11UriWrapped,
    private_key_operation: bool,
) -> Result<(String, String, Option<u64>)> {
    if private_key_operation && !p11uriw.has_pin() {
        return Err(anyhow!("Missing PIN for private key operation"));
    }
    // some devices require a PIN to find a *public* key object, others don't
    let pin = p11uriw.pin()?;
    let module_name = p11uriw.module()?;
    let slotid = p11uriw.p11uri.path_attributes.slot_id;
    Ok((pin, module_name, slotid))
}

/// Get the key label by retrieving the value of the 'object' attribute.
fn pkcs11_uri_get_key_id_and_label(p11uri: &Pkcs11Uri) -> Result<(&Vec<u8>, &String)> {
    let object_id = match p11uri.path_attributes.object_id.as_ref() {
        Some(x) => x,
        None => return Err(anyhow!("'object_id' attribute not found in pkcs11 URI")),
    };
    let object_label = match p11uri.path_attributes.object_label.as_ref() {
        Some(x) => x,
        None => return Err(anyhow!("'object_label' attribute not found in pkcs11 URI")),
    };
    Ok((object_id, object_label))
}

/// Use the given pkcs11 URI to select the pkcs11 module (shared libary) and to
/// get the PIN te use for login. If the URI contains a slot-id,
/// the given slot-id will be used. Otherwise, one slot after the other will be
/// attempted, and the first one where login succeeds will be used.
fn pkcs11_uri_login(
    p11uriw: &Pkcs11UriWrapped,
    private_key_operation: bool,
) -> Result<(pkcs11::Ctx, pkcs11::types::CK_SESSION_HANDLE)> {
    let p11uri = &p11uriw.p11uri;
    let (pin, module, slotid) = pkcs11_uri_get_login_parameters(p11uriw, private_key_operation)?;

    let mut p11ctx = pkcs11::Ctx::new(module)?;

    let _ = p11ctx.initialize(None);

    match slotid {
        Some(sid) => {
            let session = pkcs11_open_session(&p11ctx, sid, pin)?;
            Ok((p11ctx, session))
        }
        None => {
            let slots = p11ctx.get_slot_list(true)?;

            let tokenlabel = match p11uri.path_attributes.token_label.as_ref() {
                Some(x) => x,
                None => {
                    return Err(anyhow!(
                        "Missing 'token_label' attribute since 'slot_id' was not given"
                    ))
                }
            };

            for slot in slots {
                let ti = match p11ctx.get_token_info(slot) {
                    Ok(o) => o,
                    Err(_) => {
                        return Err(anyhow!("Failed to get token info for slot"));
                    }
                };
                if &String::from(ti.label) != tokenlabel {
                    continue;
                }

                let session = pkcs11_open_session(&p11ctx, slot, pin)?;
                return Ok((p11ctx, session));
            }
            if !pin.is_empty() {
                return Err(anyhow!(
                    "Could not create session to any slot and/or log in"
                ));
            }
            Err(anyhow!("Could not create session to any slot"))
        }
    }
}

/// Find an object of the given class with the given object_id and/or
/// object_label.
fn find_object(
    p11ctx: &pkcs11::Ctx,
    session: pkcs11::types::CK_SESSION_HANDLE,
    class: u64,
    object_id: &[u8],
    object_label: &str,
) -> Result<pkcs11::types::CK_OBJECT_HANDLE> {
    let mut msg = "".to_string();

    let mut template: Vec<pkcs11::types::CK_ATTRIBUTE> = Vec::new();
    let mut a = pkcs11::types::CK_ATTRIBUTE::new(pkcs11::types::CKA_CLASS);
    a.set_ck_ulong(&class);
    template.push(a);

    if !object_label.is_empty() {
        let mut b = pkcs11::types::CK_ATTRIBUTE::new(pkcs11::types::CKA_LABEL);
        b.set_string(object_label);
        template.push(b);
        msg += &format!("object_label '{}'", object_label);
    }
    if !object_id.is_empty() {
        let mut c = pkcs11::types::CK_ATTRIBUTE::new(pkcs11::types::CKA_ID);
        c.set_bytes(object_id);
        template.push(c);
        if !msg.is_empty() {
            msg += " and "
        }
        msg += &String::from_utf8_lossy(object_id);
    }

    match p11ctx.find_objects_init(session, &template) {
        Ok(_) => {}
        Err(_) => {
            return Err(anyhow!("find_objects_init failed"));
        }
    }

    let obj_handles = p11ctx.find_objects(session, 100)?;

    match p11ctx.find_objects_final(session) {
        Ok(_) => {}
        Err(_) => {
            return Err(anyhow!("find_objects_final failed"));
        }
    }

    match obj_handles.len().cmp(&1) {
        Ordering::Less => Err(anyhow!("Could not find any object with {}", msg)),
        Ordering::Greater => Err(anyhow!(
            "There are too many (={}) keys with {}",
            obj_handles.len(),
            msg
        )),
        Ordering::Equal => Ok(obj_handles[0]),
    }
}

fn construct_oaep_params() -> Result<(
    pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS,
    pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS,
)> {
    // FIXME ? Thread safety issue in rust when naively trying to make this
    // static-global. Is there a better way than doing this dynamically?

    // oaep_label defines the label we use for OAEP encryption; cannot be changed
    let oaep_label: *mut pkcs11::types::CK_VOID = std::ptr::null_mut();
    let label_len: pkcs11::types::CK_ULONG = 0;

    // oaep_sha1_params describes the OAEP parameters with sha1 hash algorithm;
    // needed by SoftHSM
    let oaep_sha1_params: pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS =
        pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: pkcs11::types::CKM_SHA_1,
            mgf: pkcs11::types::CKG_MGF1_SHA1,
            source: pkcs11::types::CKZ_DATA_SPECIFIED,
            pSourceData: oaep_label,
            ulSourceDataLen: label_len,
        };

    // oaep_sha256_params describes the OAEP parameters with sha256 hash
    // algorithm
    let oaep_sha256_params: pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS =
        pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: pkcs11::types::CKM_SHA256,
            mgf: pkcs11::types::CKG_MGF1_SHA256,
            source: pkcs11::types::CKZ_DATA_SPECIFIED,
            pSourceData: oaep_label,
            ulSourceDataLen: label_len,
        };

    Ok((oaep_sha1_params, oaep_sha256_params))
}

fn oaep_hashalg(oaephash: String) -> Result<(pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS, String)> {
    let oaep_params = construct_oaep_params()?;
    let oaep_sha1_params = oaep_params.0;
    let oaep_sha256_params = oaep_params.1;
    let tmp = match oaephash.to_lowercase().as_str() {
        "" => (oaep_sha1_params, "sha1".to_string()),
        "sha1" => (oaep_sha1_params, "sha1".to_string()),
        "sha256" => (oaep_sha256_params, "sha256".to_string()),
        // FIXME: _ case should return nil and error
        _ => (oaep_sha256_params, "sha256".to_string()),
    };
    Ok(tmp)
}
fn oaep(hashalg: &str) -> Result<pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS> {
    let oaep_params = construct_oaep_params()?;
    let oaep_sha1_params = oaep_params.0;
    let oaep_sha256_params = oaep_params.1;
    let oaep = match hashalg.to_lowercase().as_str() {
        "sha1" | "" => oaep_sha1_params,
        "sha256" => oaep_sha256_params,
        // FIXME: _ case should error
        _ => oaep_sha256_params,
    };
    Ok(oaep)
}

/// Encrypt plaintext with the given RsaPublicKey.
/// The environment variable OCICRYPT_OAEP_HASHALG can be set to 'sha1' to
/// force usage of sha1 for OAEP (SoftHSM). This function is needed by clients
/// who are using a public key file for pkcs11 encryption.
fn rsa_public_encrypt_oaep(pubkey: &RsaPublicKey, plaintext: &[u8]) -> Result<(Vec<u8>, String)> {
    let oaephash: String = match std::env::var("OCICRYPT_OAEP_HASHALG") {
        Ok(o) => o,
        Err(_) => {
            return Err(anyhow!(
                "OCICRYPT_OAEP_HASHALG environment is not
                                      present or is invalid unicode"
            ))
        }
    };

    let padding: PaddingScheme;
    let hashalg: &str;

    match oaephash.to_lowercase().as_str() {
        "sha1" => {
            hashalg = "sha1";
            padding = PaddingScheme::new_oaep::<Sha1>();
        }
        "sha256" => {
            hashalg = "sha256";
            padding = PaddingScheme::new_oaep::<Sha256>();
        }
        _ => {
            return Err(anyhow!("Unsupported OAEP hash '{}'", oaephash));
        }
    }

    let mut rng = OsRng;
    let ciphertext = pubkey.encrypt(&mut rng, padding, plaintext)?;
    Ok((ciphertext, hashalg.to_string()))
}

/// Use a public key described by a pkcs11 URI to OAEP encrypt the given
/// plaintext.
fn public_encrypt_oaep(
    pub_key: &Pkcs11KeyFileObject,
    plaintext: &[u8],
) -> Result<(Vec<u8>, String)> {
    // TODO
    // defer restoreEnv(oldenv)
    // defer pkcs11Logout(p11ctx, session)
    let _oldenv = set_env_vars(pub_key.uriw.env_map());

    let p11ctx_session = pkcs11_uri_login(&pub_key.uriw, false)?;
    let p11ctx = p11ctx_session.0;
    let session = p11ctx_session.1;

    let object_id_label = pkcs11_uri_get_key_id_and_label(&pub_key.uriw.p11uri)?;
    let object_id = object_id_label.0;
    let object_label = object_id_label.1;

    let p11_pub_key = find_object(
        &p11ctx,
        session,
        pkcs11::types::CKO_PUBLIC_KEY,
        object_id,
        object_label,
    )?;

    let oaephash = match std::env::var("OCICRYPT_OAEP_HASHALG") {
        Ok(x) => x,
        Err(e) => {
            return Err(anyhow!(
                "Failed to get OCICRYPT_OAEP_HASHALG env var: {}",
                e
            ))
        }
    };

    let oaep_hashalg = oaep_hashalg(oaephash)?;

    let mut oaep = oaep_hashalg.0;
    let hashalg = oaep_hashalg.1;

    let oaep_p: *mut pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS = &mut oaep;

    let mech = pkcs11::types::CK_MECHANISM {
        mechanism: pkcs11::types::CKM_RSA_PKCS_OAEP,
        pParameter: oaep_p as *mut pkcs11::types::CK_VOID,
        ulParameterLen: std::mem::size_of_val(&oaep) as u64,
    };
    let _ = p11ctx.encrypt_init(session, &mech, p11_pub_key)?;
    let ciphertext = p11ctx.encrypt(session, plaintext)?;
    Ok((ciphertext, hashalg))
}

/// Encrypt for one or multiple pkcs11 devices. The public keys passed to this
/// function may either be *rsa.PublicKey or *pkcs11uri.Pkcs11URI; the returned
/// byte array is a JSON string of the following format:
/// {
///   recipients: [  // recipient list
///     {
///        "version": 0,
///        "blob": <base64 encoded RSA OAEP encrypted blob>,
///        "hash": <hash used for OAEP other than 'sha256'>
///     } ,
///     {
///        "version": 0,
///        "blob": <base64 encoded RSA OAEP encrypted blob>,
///        "hash": <hash used for OAEP other than 'sha256'>
///     } ,
///     [...]
///   ]
/// }
pub fn encrypt_multiple(pub_keys: &[Pkcs11KeyType], data: &[u8]) -> Result<Vec<u8>> {
    let mut pkcs11_blob: Pkcs11Blob = Pkcs11Blob {
        version: 0,
        recipients: Vec::new(),
    };
    for pub_key in pub_keys {
        let (ciphertext, hashalg): (Vec<u8>, String) = match pub_key {
            Pkcs11KeyType::RPK(r) => rsa_public_encrypt_oaep(r, data)?,
            Pkcs11KeyType::PKFO(p) => public_encrypt_oaep(p, data)?,
        };

        let recipient = Pkcs11Recipient {
            version: 0,
            blob: base64::encode(ciphertext),
            hash: hashalg,
        };
        pkcs11_blob.recipients.push(recipient);
    }
    Ok(serde_json::to_vec(&pkcs11_blob)?)
}

/// Use a pkcs11 URI describing a private key to OAEP decrypt a ciphertext.
fn private_decrypt_oaep(
    priv_key: &Pkcs11KeyFileObject,
    ciphertext: &[u8],
    hashalg: &str,
) -> Result<Vec<u8>> {
    // FIXME remove boilerplate similar to public_encrypt_oaep
    // TODO
    // defer restoreEnv(oldenv)
    // defer pkcs11Logout(p11ctx, session)
    let _oldenv = set_env_vars(priv_key.uriw.env_map());

    let p11ctx_session = pkcs11_uri_login(&priv_key.uriw, true)?;
    let p11ctx = p11ctx_session.0;
    let session = p11ctx_session.1;

    let object_id_label = pkcs11_uri_get_key_id_and_label(&priv_key.uriw.p11uri)?;
    let object_id = object_id_label.0;
    let object_label = object_id_label.1;

    let p11_priv_key = find_object(
        &p11ctx,
        session,
        pkcs11::types::CKO_PRIVATE_KEY,
        object_id,
        object_label,
    )?;

    let mut oaep = oaep(hashalg)?;

    // FIXME: boilerplate similar to public_encrypt_oaep

    let oaep_p =
        &mut oaep as pkcs11::types::CK_RSA_PKCS_OAEP_PARAMS_PTR as pkcs11::types::CK_VOID_PTR;

    let mech = pkcs11::types::CK_MECHANISM {
        mechanism: pkcs11::types::CKM_RSA_PKCS_OAEP,
        pParameter: oaep_p,
        ulParameterLen: std::mem::size_of_val(&oaep) as u64,
    };

    let _ = p11ctx.decrypt_init(session, &mech, p11_priv_key)?;

    let plaintext = p11ctx.decrypt(session, ciphertext)?;

    Ok(plaintext)
}

/// Try to decrypt one of the recipients' blobs using a pkcs11 private key.
/// The input pkcs11blobstr is a string with the following format:
/// {
///   recipients: [  // recipient list
///     {
///        "version": 0,
///        "blob": <base64 encoded RSA OAEP encrypted blob>,
///        "hash": <hash used for OAEP other than 'sha256'>
///     } ,
///     {
///        "version": 0,
///        "blob": <base64 encoded RSA OAEP encrypted blob>,
///        "hash": <hash used for OAEP other than 'sha256'>
///     } ,
///     [...]
/// }
pub fn decrypt_pkcs11(
    priv_keys: &[Box<Pkcs11KeyFileObject>],
    pkcs11blobstr: &[u8],
) -> Result<Vec<u8>> {
    let pkcs11_blob: Pkcs11Blob = serde_json::from_slice(pkcs11blobstr)?;
    if pkcs11_blob.version != 0 {
        return Err(anyhow!(
            "Found Pkcs11Blob with version {} but maximum supported version is 0.",
            pkcs11_blob.version
        ));
    }
    // since we do trial and error, collect all encountered errors
    let mut errs = String::from("");

    for recipient in pkcs11_blob.recipients {
        if recipient.version != 0 {
            return Err(anyhow!(
                "Found Pkcs11Recipient with version {} but maximum supported version is 0.",
                recipient.version
            ));
        }

        let ciphertext = match base64::decode(recipient.blob) {
            Ok(c) => {
                if c.is_empty() {
                    errs += "Base64 decoding yielded empty ciphertext\n";
                    continue;
                }
                c
            }
            Err(e) => {
                errs += &format!("Base64 decoding failed: {}\n", e);
                continue;
            }
        };
        // try all keys until one works
        for priv_key in priv_keys {
            let plaintext = private_decrypt_oaep(priv_key, &ciphertext, &recipient.hash);
            match plaintext {
                Ok(x) => {
                    return Ok(x);
                }
                Err(e) => {
                    errs += &format!("{:?} : {}", priv_key.uriw.p11uri, e);
                }
            }
        }
    }

    Err(anyhow!(
        "Could not find a pkcs11 key for decryption: {}",
        errs
    ))
}
