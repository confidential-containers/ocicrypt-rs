//
// FIXME is_allowed_path(), module(), these extra fields that had to be put
// into Pkcs11UriWrapped, etc. are all based on the  the golang version of
// pkcs11-uri. They may need to be PRs for pkcs11-uri rust package.
//

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use pkcs11_uri::{Pkcs11Uri};
use http::Uri;

pub struct Pkcs11UriWrapped {
    pub p11uri: Pkcs11Uri,
    // directories to search for pkcs11 modules
    module_directories: Vec<String>,
    // file paths of allowed pkcs11 modules
    allowed_module_paths: Vec<String>,
    // whether any module is allowed to be loaded
    allow_any_module: bool,
    // A map of environment variables needed by the pkcs11 module using this URI.
    // This map is not needed by this implementation but is there for convenience.
    env: HashMap<String, String>,
}


impl Pkcs11UriWrapped {

    // Constructs a new Pkcs11UriWrapped instance
    pub fn new(uri: Pkcs11Uri) -> Result<Self> {
        Ok(Pkcs11UriWrapped{
            p11uri: uri,
            module_directories: vec![],
            allowed_module_paths: vec![],
            allow_any_module: false,
            env: HashMap::new(),
        })
    }

    // Get the map of environment variables
    pub fn env_map(&self) -> &HashMap<String, String> {
        &self.env
    }

    // Set the environment variables for the pkcs11 module
    pub fn set_env_map(&mut self, env: HashMap<String, String>) {
        self.env = env;
    }

    // Set the search directories for pkcs11 modules
    //func (uri *Pkcs11URI) SetModuleDirectories(moduleDirectories []string) {
    pub fn set_module_directories(&mut self, module_directories: &Vec<String>) {
        self.module_directories = module_directories.to_vec();
    }

    // Set allowed module paths to restrict access to modules.
    // Directory entries must end with a '/'.
    // All other ones are assumed to be file entries.
    // Allowed modules are filtered by string matching.
    pub fn set_allowed_module_paths(&mut self, allowed_module_paths: &Vec<String>) {
        self.allowed_module_paths = allowed_module_paths.to_vec();
    }

    // Get the search directories for pkcs11 modules
    pub fn module_directories(&self) -> &Vec<String> {
        &self.module_directories
    }

    pub fn is_allowed_path(&self,
                           path: &String,
                           allowed_paths: &Vec<String>,
    ) -> Result<bool> {
        if self.allow_any_module {
            return Ok(true);
        }
        for allowed_path in allowed_paths {
            if allowed_path == path {
                // exact filename match
                return Ok(true);
            }
            // FIXME: replace with idiomatic rust
            let ap_bytes = allowed_path.as_bytes();
            let last_byte: u8 = ap_bytes[ap_bytes.len()-1];
            if last_byte == b'/' && path.starts_with(allowed_path) {
                // allowed_path no subdirectory is allowed
                let p_bytes = path.as_bytes();
                let some_slice = &p_bytes[ap_bytes.len()..];
                let mut has_separator = false;
                for b in some_slice {
                    if *b as char == std::path::MAIN_SEPARATOR {
                        has_separator = true;
                        break;
                    }
                }
                if !has_separator {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    // Get the PIN from either the pin-value or pin-source attribute; a
    // user may want to call HasPIN() before calling this function to determine
    // whether a PIN has been provided at all so that an error code returned by
    // this function indicates that the PIN value could not be retrieved.
    pub fn pin(&self) -> Result<String> {
        match &self.p11uri.query_attributes.pin_value {
            Some(x) => return Ok(x.to_string()),
            None => {},
        }
        match &self.p11uri.query_attributes.pin_source {
            Some(v) => {
                let pinuri = &v.parse::<Uri>()?;
                let p = match pinuri.scheme_str() {
                    Some(x) => x,
                    None => return Err(anyhow!("")),
                };
                match p {
                    "" | "file" => {
                        if !std::path::Path::new(pinuri.path()).is_absolute() {
                            return Err(anyhow!("PIN URI path {} is not absolute", pinuri.path()));
                        }
                        let pin = std::fs::read_to_string(pinuri.path())?;
                        return Ok(pin)
                    },
                    _ => {
                        let ss = pinuri.scheme_str();
                        match ss {
                            Some(s) => return Err(anyhow!("PIN URI scheme {} is not supported", s)),
                            None => return Err(anyhow!("failed to get scheme from pin URI")),
                        }
                    },
                }
            },
            None => {},
        }
        // FIXME error
        Err(anyhow!("Neither pin-source nor pin-value are available"))
    }


    // has_pin allows the user to check whether a PIN has been provided either by
    // the pin-value or the pin-source attributes. It should be called before
    // pin(), which may still fail getting the PIN from a file for example.
    pub fn has_pin(&self) -> bool {
        match &self.p11uri.query_attributes.pin_value {
            Some(_x) => return true,
            None => {},
        }
        match &self.p11uri.query_attributes.pin_source {
            Some(_x) => return true,
            None => {},
        }
        false
    }


    // Get the module to use or an error in case no module could be found.
    // First the module-path is checked for whether it holds an absolute that
    // can be read by the current user. If this is the case the module is
    // returned. Otherwise either the module-path is used or the user-provided
    // module path is used to match a module containing what is set in the
    // attribute module-name.
    pub fn module(&self) -> Result<String> {
        let searchdirs_tmp: Vec<String>; // FIXME
        let searchdirs: &Vec<String>;

        if let Some(mp) = &self.p11uri.query_attributes.module_path {
            let info = std::fs::metadata(mp)?;
            if info.is_file() {
                // it's a file
                if self.is_allowed_path(&mp, &self.allowed_module_paths)? {
                    return Ok(mp.to_string());
                }
                return Err(anyhow!(""));
            }
            if !info.is_dir() {
                // it's a symlink
                return Err(anyhow!(""));
            }
            // it's a dir
            searchdirs_tmp = vec![mp.to_string()];
            searchdirs = &searchdirs_tmp;
        } else {
            searchdirs = &self.module_directories;
        }

        let module_name = match &self.p11uri.query_attributes.module_name {
            Some(mn) => mn.to_lowercase(),
            None => return Err(anyhow!("")),
        };

        for dir in searchdirs {
            let file_results = match std::fs::read_dir(dir) {
                Ok(fr) => fr,
                Err(e) => continue,
            };
            for file_result in file_results {
                let file = match file_result {
                    Ok(f) => f,
                    Err(e) => continue,
                };
                let file_lower = match file.file_name().into_string() {
                    Ok(f) => f.to_lowercase(),
                    Err(e) => continue,
                };
                let idx = match file_lower.find(&module_name) {
                    Some(i) => i,
                    None => continue,
                };
                // We require that file_lower ends with module_name or that
                // a suffix follows so that softhsm will not match
                // libsofthsm2.so but only libsofthsm.so
                // FIXME: replace with idiomatic rust
                if file_lower.len() == idx+module_name.len()
                || file_lower.as_bytes()[idx+module_name.len()] == b'.' {
                    let f = std::path::Path::new(dir).join(file.file_name());
                    // TODO
                    let fstr = f.as_path().display().to_string();
                    if self.is_allowed_path(&fstr, &self.allowed_module_paths)? {
                        return Ok(fstr);
                    }
                    return Err(anyhow!(""));
                }
            }
        }
        Err(anyhow!("No module could be found"))
    }
}
