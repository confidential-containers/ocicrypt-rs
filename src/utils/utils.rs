use ::pem::parse;
use der_parser::parse_der;
use std::collections::HashMap;
use pkcs8::{FromPrivateKey};
use openssl::x509::X509;
use anyhow::{anyhow, Result};
use x509_parser::prelude::*;
use josekit::jwk::Jwk;

/*
TODO:
- parsePkcs11PrivateKeyYaml - done in other PR
- parsePkcs11PublicKeyYaml - done in other PR
- ParsePrivateKey - TODO in PR
- ParsePublicKey - TODO in PR
- IsPkcs11PrivateKey - TODO in PR
- IsPkcs11PublicKey - TODO in PR
- IsGPGPrivateKeyRing
- testing
*/


// parse_jwk_private_key parses the input byte array as a JWK and makes sure it's a private key
pub fn parse_jwk_private_key(priv_key: &Vec<u8>, prefix: &String) -> Result<Jwk> {
    let jwk_format = Jwk::from_bytes(priv_key)?;
    let jwk_temp_copy = jwk_format.to_public_key()?;

    if jwk_format != jwk_temp_copy { 
        return Ok(jwk_format)
    } else {
        return Err(anyhow!("{}: JWK is not a private key", prefix));
    }
}

// parse_jwk_public_key parses the input byte array as a JWK and makes sure it's a public key
pub fn parse_jwk_public_key(pub_key: &Vec<u8>, prefix: &String) -> Result<Jwk> {
    let jwk_format = Jwk::from_bytes(pub_key)?;
    let jwk_temp_copy = jwk_format.to_public_key()?;

    if jwk_format == jwk_temp_copy { 
        return Ok(jwk_format)
    } else {
        return Err(anyhow!("{}: JWK is not a public key", prefix));
    }
}

// parse_private_key tries to parse a private key in DER format first and
// PEM format after, returning an error if the parsing failed
pub fn parse_private_key(priv_key: &Vec<u8>, priv_key_password: &Vec<u8>, prefix: &String) -> Result<()> {
    return Err(anyhow!(""));
}

// TODO: return error if is not private key
fn is_private_key(data: &Vec<u8>, password: &Vec<u8>) -> bool {
    match parse_private_key(data, password, &"".to_string()) {
        Ok(_) => return true,
        Err(_) => return false, 
    }
}

// TODO
pub fn parse_pkcs11_public_key_yaml(pub_key: &Vec<u8>, prefix: &String) -> Result<()> {
    return Err(anyhow!(""));
}

// TODO: implement parse_pkcs11_public_key_yaml
fn parse_jwk_and_pkcs11_public_key(pub_key: &Vec<u8>, prefix: &String) -> Result<()> {
    match parse_jwk_public_key(pub_key, prefix) {
        Ok(o) => { 
            return Ok(())
        },
        Err(_) => {
            return parse_pkcs11_public_key_yaml(pub_key, prefix);
        }
    }
}

// TODO: change return type
pub fn parse_public_key(pub_key: &Vec<u8>, prefix: &String) -> Result<()> {
    match parse_der(pub_key) { // try to parse in der format
        Ok((rest, result)) => {
            if rest.len() > 0 {
                return parse_jwk_and_pkcs11_public_key(pub_key, prefix);
            }
            else { // Parsed public key in der format
                return Ok(())   
            }
        },
        Err(_) => {
            match parse(pub_key) { // try to parse in pem format
                Ok(o) => { // Parsed public key in pem format
                    return Ok(())
                },
                Err(_) => {
                    return parse_jwk_and_pkcs11_public_key(pub_key, prefix);
                }
            }
        }
    }
}

fn is_public_key(data: &Vec<u8>) -> bool {
    match parse_public_key(data, &"".to_string()) {
        Ok(_) => return true,
        Err(_) => return false,
    }
}


// parse_certificate tries to parse a public key in DER format first and
// PEM format after, returning an error if the parsing failed
fn parse_certificate<'a>(cert_bytes: &'a Vec<u8>, prefix: &String) -> Result<X509Certificate<'a>> {
    let res = X509Certificate::from_der(cert_bytes);
    match res {
        Ok(_) => (),
        Err(_) => {
            let res = parse_x509_pem(cert_bytes);
            match res {
                Ok(_) => (),
                Err(_) => return Err(anyhow!("{}: Could not parse x509 certificate", prefix))
            }
        }
    }

    Ok(res.unwrap().1)
}

// is_certificate returns true in case the given byte array represents an x.509 certificate
fn is_certificate(data: &Vec<u8>) -> bool {
    match parse_certificate(data, &String::new()) {
        Ok(_) => return true,
        Err(_) => return false,
    }
}


// TODO
// is_gpg_private_key_ring returns true in case the given byte array represents a GPG private key ring file
fn is_gpg_private_key_ring(data: &Vec<u8>) -> bool {
    return false;
}

// TODO: implement is_password_error 
fn is_password_error() -> bool {
    return false;
}

// sort_decryption_key parses a list of comma separated base64 entries and sorts the data into
// a map. Each entry in the list may be either a GPG private key ring, private key, or x.509
// certificate
fn sort_decryption_key(b64_item_list: &String) -> Result<HashMap<String, Vec<Vec<u8>>>> {
    let mut dc_parameters: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

    for b64_item in b64_item_list.split(",") {
        let mut password: Vec<u8> = Vec::new();
        let b64_data: Vec<&str> = b64_item.split(":").collect();
        let key_data = base64::decode(b64_data[0]).unwrap();

        if b64_data.len() == 2 {
            password = base64::decode(b64_data[1])?;
        }

        let mut key: String = String::new();
        let is_priv_key = is_private_key(&key_data, &password);

        // TODO: implement is_password_error function
        if is_password_error() {
            return Err(anyhow!("Wrong password"));
        }

        if is_priv_key {
            key = "privkeys".to_string();
            if !dc_parameters.contains_key(&"privkeys-passwords".to_string()) {
                let mut v: Vec<Vec<u8>> = Vec::new();
                v.push(password);
                dc_parameters.insert("privkeys-passwords".to_string(), v);
            }
            else {
                dc_parameters.entry("privkeys-passwords".to_string()).or_default().push(password);
            }
        }
        else if is_certificate(&key_data) {
            key = "x509s".to_string();
        }
        else if is_gpg_private_key_ring(&key_data) {
            key = "gpg-privatekeys".to_string();
        }

        if key != "".to_string() {
            if !dc_parameters.contains_key(&key) {
                let mut v: Vec<Vec<u8>> = Vec::new();
                v.push(key_data);
                dc_parameters.insert(key, v);
            } 
            else {
                dc_parameters.entry(key).or_default().push(key_data);
            }
        }
        else {
            return Err(anyhow!("Unknown decryption key type"));
        }

    }

    return Ok(dc_parameters);
}