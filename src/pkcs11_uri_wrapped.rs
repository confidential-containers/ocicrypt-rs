// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

//
// FIXME is_allowed_path(), module(), these extra fields that had to be put
// into Pkcs11UriWrapped, etc. are all based on the  the golang version of
// pkcs11-uri. They may need to be PRs for pkcs11-uri rust package.
//

use anyhow::{anyhow, Result};
use http::Uri;
use pkcs11_uri::Pkcs11Uri;
use std::collections::HashMap;

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
    pub fn new(uri: Pkcs11Uri) -> Self {
        Pkcs11UriWrapped {
            p11uri: uri,
            module_directories: vec![],
            allowed_module_paths: vec![],
            allow_any_module: false,
            env: HashMap::new(),
        }
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
        self.module_directories = module_directories.clone();
    }

    // Set allowed module paths to restrict access to modules.
    // Directory entries must end with a '/'.
    // All other ones are assumed to be file entries.
    // Allowed modules are filtered by string matching.
    pub fn set_allowed_module_paths(&mut self, allowed_module_paths: &Vec<String>) {
        self.allowed_module_paths = allowed_module_paths.clone();
    }

    // Get the search directories for pkcs11 modules
    pub fn module_directories(&self) -> &Vec<String> {
        &self.module_directories
    }

    // Check if a path is allowed.
    pub fn is_allowed_path(&self, path: &String, allowed_paths: &Vec<String>) -> Result<bool> {
        // case 1: if any module is allowed, it's allowed
        if self.allow_any_module {
            return Ok(true);
        }
        for allowed_path in allowed_paths {
            if allowed_path == path {
                // case 2: path is an exact match with an allowed path
                return Ok(true);
            }
            // case 3: path matches some allowed path, and path has more
            // characters beyond /. As long as there are no more
            // subdirectories, it's allowed.
            if allowed_path.ends_with("/") {
                if let Some(suffix) = path.strip_prefix(allowed_path) {
                    if !suffix.contains(std::path::MAIN_SEPARATOR) {
                        return Ok(true);
                    }
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
        if let Some(pv) = &self.p11uri.query_attributes.pin_value {
            return Ok(pv.to_string());
        }
        if let Some(ps) = &self.p11uri.query_attributes.pin_source {
            let pinuri = &ps.parse::<Uri>()?;
            match pinuri.scheme_str() {
                Some("") | Some("file") => {
                    if !std::path::Path::new(pinuri.path()).is_absolute() {
                        return Err(anyhow!("PIN URI path {} is not absolute", pinuri.path()));
                    }
                    return Ok(std::fs::read_to_string(pinuri.path())?);
                }
                Some(s) => return Err(anyhow!("PIN URI scheme {} is not supported", s)),
                None => return Err(anyhow!("failed to get scheme from pin URI")),
            }
        }
        Err(anyhow!("Neither pin-source nor pin-value are available"))
    }

    // has_pin allows the user to check whether a PIN has been provided either by
    // the pin-value or the pin-source attributes. It should be called before
    // pin(), which may still fail getting the PIN from a file for example.
    pub fn has_pin(&self) -> bool {
        match &self.p11uri.query_attributes.pin_value {
            Some(_x) => return true,
            None => {}
        }
        match &self.p11uri.query_attributes.pin_source {
            Some(_x) => return true,
            None => {}
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
        let searchdirs_tmp: Vec<String>;
        let searchdirs: &Vec<String>;

        if let Some(mp) = &self.p11uri.query_attributes.module_path {
            let info = std::fs::metadata(mp)?;
            if info.is_file() {
                // it's a file
                if self.is_allowed_path(&mp, &self.allowed_module_paths)? {
                    return Ok(mp.to_string());
                }
                return Err(anyhow!("module-path '{}' is not allowed by policy", mp));
            }
            if !info.is_dir() {
                // it's a symlink
                return Err(anyhow!(
                    "module-path '{}' points to an invalid file type",
                    mp
                ));
            }
            // it's a dir
            searchdirs_tmp = vec![mp.to_string()];
            searchdirs = &searchdirs_tmp;
        } else {
            searchdirs = &self.module_directories;
        }

        let module_name = match &self.p11uri.query_attributes.module_name {
            Some(mn) => mn,
            None => return Err(anyhow!("module-name attribute is not set")),
        };

        for dir in searchdirs {
            let file_results = match std::fs::read_dir(dir) {
                Ok(fr) => fr,
                Err(e) => continue,
            };
            for file_result in file_results {
                let file = match file_result {
                    Ok(f) => match f.file_name().into_string() {
                        Ok(ff) => ff,
                        Err(e) => continue,
                    },
                    Err(e) => continue,
                };
                let idx = match file.find(module_name) {
                    Some(i) => i,
                    None => continue,
                };
                // We require that file ends with module_name or that
                // a suffix follows so that softhsm will not match
                // libsofthsm2.so but only libsofthsm.so
                if file.len() == idx + module_name.len()
                    || file.as_bytes()[idx + module_name.len()] == b'.'
                {
                    let pathbuf = std::path::Path::new(dir).join(file);
                    let pathname = pathbuf.as_path().display().to_string();
                    if self.is_allowed_path(&pathname, &self.allowed_module_paths)? {
                        return Ok(pathname);
                    }
                    return Err(anyhow!("module '{}' is not allowed by policy", pathname));
                }
            }
        }
        Err(anyhow!("No module could be found"))
    }
}
