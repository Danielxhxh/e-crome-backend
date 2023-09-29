mod utils;

use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;


extern crate rabe;
use crate::rabe::schemes::*;
use rabe::utils::policy::pest::PolicyLanguage;

use js_sys::{JsString, Array, Uint8Array, Error, TypeError, SyntaxError};
use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;

extern crate rabe_bn;
use rabe_bn::{G1, Gt};

#[derive(Serialize, Deserialize)]
#[derive(Clone)]
#[wasm_bindgen]
pub enum PolicyLanguageRabe {
    JsonPolicy = 0,
    HumanPolicy = 1,
}

#[derive(Serialize, Deserialize)]
#[wasm_bindgen]
pub struct CpAbeCiphertext {
    policy : String,
    policy_language : PolicyLanguageRabe,
    c : String,
    c_p : String,
    c_y : String,
    ct : Vec<u8>,
}

#[wasm_bindgen]
impl CpAbeCiphertext {
    #[wasm_bindgen(constructor)]
    pub fn new(
        policy : String,
        policy_language : PolicyLanguageRabe,
        c : String,
        c_p : String,
        c_y : String,
        ct : Vec<u8>
        ) -> CpAbeCiphertext {
            CpAbeCiphertext { 
                policy,
                policy_language,
                c,
                c_p,
                c_y,
                ct
            }
    }

    //#[wasm_bindgen(getter = policy)]
    pub fn get_policy(&self) -> String {
        self.policy.clone()
    }
    
    //#[wasm_bindgen(setter = policy)]
    pub fn set_policy(&mut self, val: String) {
        self.policy = val;
    }

    pub fn get_policy_language(&self) -> PolicyLanguageRabe {
        self.policy_language.clone()
    }
    
    pub fn set_policy_language(&mut self, val: PolicyLanguageRabe) {
        self.policy_language = val;
    }
    
    pub fn get_c(&self) -> String {
        self.c.to_string()
    }
    
    pub fn set_c(&mut self, val: String) {
        self.c = val;
    }
    pub fn get_c_p(&self) -> String {
        self.c_p.to_string()
    }
    
    pub fn set_c_p(&mut self, val: String) {
        self.c_p = val;
    }
    pub fn get_c_y(&self) -> String {
        self.c_y.to_string()
    }
    
    pub fn set_c_y(&mut self, val: String) {
        self.c_y = val;
    }

    pub fn get_ct(&self) -> Vec<u8> {
        self.ct.clone()
    }
    
    pub fn set_ct(&mut self, val: Vec<u8>) {
        self.ct = val;
    }

}

fn get_rabe_error_details(err : rabe::error::RabeError) 
    -> Result<String, Error>{
        Ok(err.to_string().replace("Error: ", ""))
}

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

fn attributes_to_or_human_policy(attributes: &Array) 
    -> Result<String, Error> {

        let mut attributes_vec: Vec<String> = Vec::new();
        for i in 0..attributes.length() {
            if !attributes.get(i).is_string() {
                return Err(TypeError::new(&format!("the given attribute set contains non-string value at position {}", i)).into())
            }
            attributes_vec.push(format!(r#""{}""#,attributes.get(i).as_string().unwrap()));
        }

        let human_policy = attributes_vec.join(" or ");
        console_log!("attributes => HumanPolicy:{}", human_policy);
        Ok(human_policy)
}

pub fn controllo_string(val : &JsString, name : String) 
    -> Result<(), Error> {
    if !val.is_string() {
        if val.is_null() {
            return Err(TypeError::new(&format!("the given {} is null", name)).into())
        }

        return Err(TypeError::new(&format!("the given {} must be of String type", name)).into())
    }

    if val.length() == 0 {
        return Err(TypeError::new(&format!("the {} policy is empty", name)).into())
    }

    Ok(())
}

/// Algoritmo setup di rabe BSW CP-ABE. Genera una nuova PK e una nuova MSK.
#[wasm_bindgen]
pub fn bsw_setup() 
    -> Result<Array, Error>{
        utils::set_panic_hook();
        let (pk, msk) = bsw::setup();

        let pk_result = JsValue::from(serde_json::to_string(&pk).unwrap());
        let msk_result = JsValue::from(serde_json::to_string(&msk).unwrap());

        let result = Array::new_with_length(2);
        result.set(0, pk_result);
        result.set(1, msk_result);
        Ok(result)
}

/// Algoritmo keygen di rabe BSW CP-ABE.
/// Genera una SecretKey (SK) usando una PK, una MSK e un set di attributi.
///
/// # Arguments
///
///	* `pk` - Una Public Key (PK), generata dalla funzione bsw_setup()
///	* `msk` - Una Master Key (MSK), generata dalla funzione bsw_setup()
///	* `attributes` - Un Array di attributi di tipo String da assegnare all'user key
///
#[wasm_bindgen]
pub fn bsw_keygen(
    pk: JsString, 
    msk: JsString, 
    attributes: Array
) -> Result<String, Error> {

    controllo_string(&pk, String::from("pk"))?;
    controllo_string(&msk, String::from("msk"))?;

    if !Array::is_array(&attributes) {
        if attributes.is_null() {
            return Err(TypeError::new("the given attribute set is null").into())
        }

        return Err(TypeError::new("the given attribute set must be of Array type").into())
    }

    if attributes.length() == 0 {
        return Err(TypeError::new("the given attribute set is empty").into())
    }

    let mut attributes_vec: Vec<String> = Vec::new();
    for i in 0..attributes.length() {
        if !attributes.get(i).is_string() {
            return Err(TypeError::new(&format!("the given attribute set contains non-string value at position {}", i)).into())
        }
        attributes_vec.push(attributes.get(i).as_string().unwrap());
    }

    let _pk: bsw::CpAbePublicKey = match serde_json::from_str(&<JsString as Into<String>>::into(pk)) {
        Ok(_pk) => { _pk },
        Err(_error) => return Err(SyntaxError::new(&format!("error while parsing pk string: {}", _error)).into()),
    };
    
    let _msk: bsw::CpAbeMasterKey = match serde_json::from_str(&<JsString as Into<String>>::into(msk)) {
        Ok(_msk) => { _msk },
        Err(_error) => return Err(SyntaxError::new(&format!("error while parsing msk string: {}", _error)).into()),
    };

    match bsw::keygen(&_pk, &_msk, &attributes_vec) {
        Some(sk) => Ok(serde_json::to_string(&sk).unwrap()),
        None => return Err(TypeError::new("attributes is_empty or len() == 0").into()),
    }
}

/// Algoritmo encrypt di rabe BSW CP-ABE.
/// Genera un nuovo CpAbeCiphertext usando una PK, una policy, del plaintext e il tipo del linguaggio della policy.
///
/// # Arguments
///
///	* `pk` - Una Public Key (PK), generata dalla funzione bsw_setup()
///	* `policy` - Una policy di tipo String
///	* `plaintext` - Un Uint8Array con i dati da cifrare
///	* `language` - Una PolicyLanguageRabe che definisce il linguaggio della policy
///
#[wasm_bindgen]
pub async fn bsw_encrypt(pk : JsString, 
    policy : JsString, 
    plaintext : Uint8Array,
    language : PolicyLanguageRabe,
    ) 
    -> Result<CpAbeCiphertext, Error> {
    utils::set_panic_hook();
        
    controllo_string(&pk, String::from("pk"))?;
    controllo_string(&policy, String::from("policy"))?;

    if !plaintext.is_instance_of::<Uint8Array>() {
        return Err(TypeError::new("the given plaintext must be of Uint8Array type").into())
    }

    if plaintext.is_null() {
        return Err(TypeError::new("the given plaintext is null").into())
    }

    if plaintext.length() == 0 {
        return Err(TypeError::new("the given plaintext is empty").into())
    }

    let _pk: bsw::CpAbePublicKey = match serde_json::from_str(&<JsString as Into<String>>::into(pk)) {
        Ok(_pk) => { _pk },
        Err(_error) => return Err(SyntaxError::new(&format!("error while parsing pk string: {}", _error)).into()),
    };

    let bytes: Vec<u8> = plaintext.to_vec();
    let _ct_len = bytes.len();
    let mut output : Vec<u8> = Vec::new();
    match output.try_reserve(_ct_len) {
        Ok(_) => (),
        Err(err) => return Err(Error::new(&format!("Failed to reserve memory for encrypted. {}", err)).into()),
    };
    
    let type_policy : PolicyLanguage;
    let type_policy_str : String;
    match language {
        PolicyLanguageRabe::JsonPolicy => {
            type_policy = PolicyLanguage::JsonPolicy;
            type_policy_str = String::from("JsonPolicy");
            //console_log!("bsw_encrypt_rabe:JsonPolicy");
        },
        PolicyLanguageRabe::HumanPolicy => {
            type_policy = PolicyLanguage::HumanPolicy;
            type_policy_str = String::from("HumanPolicy");
            //console_log!("bsw_encrypt_rabe:HumanPolicy");
        },
    };

    console_log!("bsw_encrypt_rabe:policy:{}, type_policy:{}", policy, type_policy_str);

    let ct_cp : bsw::CpAbeCiphertext = match bsw::encrypt(&_pk, 
        &policy.into(), &bytes, type_policy) {
            Ok(ct_cp) => { ct_cp },
            Err(err) => {
                let e = get_rabe_error_details(err).unwrap();
                match e {
                    e if e.starts_with("Json Policy Error in line") => {
                        match type_policy {
                            PolicyLanguage::JsonPolicy => {
                                return Err(Error::new(&e))
                            },
                            PolicyLanguage::HumanPolicy => {
                                return Err(Error::new(&e.replace("Json", "Human")))
                            },
                        };
                    },
                    e if e.starts_with("encryption error: \"aead::Error\"") => {
                        return Err(Error::new(&format!("an error occurred while encrypting the data, invalid or corrupt pk. {}", 
                        &e.replace("encryption error: ", ""))).into())
                    },
                    _ => return Err(Error::new(&e))
                }
            }
        };
    
    let a = CpAbeCiphertext::new(ct_cp._policy.0, language,
        serde_json::to_string(&ct_cp._c).unwrap(),
        serde_json::to_string(&ct_cp._c_p).unwrap(),
        serde_json::to_string(&ct_cp._c_y).unwrap(),
        ct_cp._ct);

    Ok(a)
}

/// Algoritmo decrypt di rabe BSW CP-ABE.
/// Ricostruisce l'originale plaintext, dato un CpAbeCiphertext e un SK compatibile
///
/// # Arguments
///
///	* `sk` - Una Secret Key (SK), generata dalla funzione bsw_keygen()
///	* `ct` - Un BSW CP-ABE Ciphertext
///
#[wasm_bindgen]
pub async fn bsw_decrypt(
    sk: JsString, 
    ct: CpAbeCiphertext
) -> Result<Uint8Array, Error> {
    utils::set_panic_hook();

    controllo_string(&sk, String::from("sk"))?;

    let _sk: bsw::CpAbeSecretKey = match serde_json::from_str(&<JsString as Into<String>>::into(sk)) {
        Ok(_sk) => { _sk },
        Err(_error) => return Err(SyntaxError::new(&format!("error while parsing sk string: {}", _error)).into()),
    };

    let c: G1 = match serde_json::from_str(&ct.get_c()) {
        Ok(c) => { c },
        Err(_error) => return Err(SyntaxError::new(&format!("error while parsing ct.c string: {}", _error)).into()),
    };

    let c_p: Gt = match serde_json::from_str(&ct.get_c_p()) {
        Ok(c_p) => { c_p },
        Err(_error) => return Err(SyntaxError::new(&format!("error while parsing ct.c_p string: {}", _error)).into()),
    };

    let c_y: Vec<bsw::CpAbeAttribute> = match serde_json::from_str(&ct.get_c_y()) {
        Ok(c_y) => { c_y },
        Err(_error) => return Err(SyntaxError::new(&format!("error while parsing ct.c_y string: {}", _error)).into()),
    };

    let _ct : Vec<u8> = ct.get_ct();
    let _ct_len = _ct.len();

    let _type_policy : PolicyLanguageRabe = ct.get_policy_language();
    let type_policy : PolicyLanguage;
    match _type_policy {
        PolicyLanguageRabe::JsonPolicy => {
            type_policy = PolicyLanguage::JsonPolicy;
        },
        PolicyLanguageRabe::HumanPolicy => {
            type_policy = PolicyLanguage::HumanPolicy;
        },
    };

    let act: bsw::CpAbeCiphertext = bsw::CpAbeCiphertext {_policy: (ct.get_policy(), 
        type_policy), _c : c , _c_p : c_p, _c_y : c_y, _ct};

    let mut output : Vec<u8> = Vec::new();
    match output.try_reserve(_ct_len) {
        Ok(_) => (),
        Err(err) => return Err(Error::new(&format!("Failed to reserve memory for decrypted. {}", err)).into()),
    };

    match bsw::decrypt(&_sk, &act) {
        Ok(plaintext_byte) => Ok(Uint8Array::from(&plaintext_byte[..])),
        Err(err) => {
            let e = get_rabe_error_details(err).unwrap();
            match e {
                e if e.starts_with("Error in bsw/encrypt: attributes do not match policy") => {
                        return Err(Error::new(&e.replace("Error in bsw/encrypt: attributes", "Attributes in secret key")))
                },
                e if e.starts_with("decryption error: \"aead::Error\"") => {
                    return Err(Error::new(&format!("an error occurred while decrypting the data, possibly due to an incorrect key or tampering with the ciphertext. {}", 
                    &e.replace("decryption error: ", ""))).into())
                },
                _ => return Err(Error::new(&e))
            };
        },
    }
}

/// Algoritmo encrypt di rabe BSW CP-ABE.
/// Genera un nuovo CpAbeCiphertext usando una PK, un plaintext e un set di attributi.
///
/// # Arguments
///
///	* `pk` - Una Public Key (PK), generata dalla funzione bsw_setup()
///	* `plaintext` - Un Uint8Array con i dati da cifrare
///	* `attributes` - Un Array di attributi di tipo String che diventeranno la policy del CpAbeCiphertext
///
#[wasm_bindgen]
pub async fn bsw_encrypt_attributes(
    pk : JsString, 
    plaintext : Uint8Array,
    attributes: Array) 
    -> Result<CpAbeCiphertext, Error> {
        utils::set_panic_hook();

        let human_policy = match attributes_to_or_human_policy(&attributes) {
            Ok(human_policy) => { human_policy },
            Err(error) => return Err(error),
        };

        match bsw_encrypt(pk, JsString::from(human_policy), plaintext, PolicyLanguageRabe::HumanPolicy).await {
            Ok(ct_cp) => Ok(ct_cp),
            Err(err) => Err(err),
        }
}

/// Algoritmo delegate di rabe BSW CP-ABE.
/// Genera una nuova SK usando una Pk, una SK e un sottoinsieme di attributi (appartenenti all'SK data).
///
/// # Arguments
///
///	* `pk` - Una Public Key (PK), generata dalla funzione bsw_setup()
///	* `sk` - Una Secret Key (SK), generata dalla funzione bsw_keygen()
///	* `attributes_subset` - Un Array di attributi di tipo String (sottoinsieme degli attributi del'sk) da assegnare alla nuova user key
///
#[wasm_bindgen]
pub fn bsw_delegate(
    pk: JsString, 
    sk: JsString, 
    attributes_subset: Array
) -> Result<String, Error> {

    controllo_string(&pk, String::from("pk"))?;
    controllo_string(&sk, String::from("sk"))?;

    if !Array::is_array(&attributes_subset) {
        if attributes_subset.is_null() {
            return Err(TypeError::new("the given attribute subset is null").into())
        }

        return Err(TypeError::new("the given attribute subset must be of Array type").into())
    }

    if attributes_subset.is_null() {
        return Err(TypeError::new("the given attribute subset is null").into())
    }

    if attributes_subset.length() == 0 {
        return Err(TypeError::new("the given attribute subset is empty").into())
    }

    let _pk: bsw::CpAbePublicKey = match serde_json::from_str(&<JsString as Into<String>>::into(pk)) {
        Ok(_pk) => { _pk },
        Err(_error) => return Err(SyntaxError::new(&format!("error while parsing pk string: {}", _error)).into()),
    };

    let _sk: bsw::CpAbeSecretKey = match serde_json::from_str(&<JsString as Into<String>>::into(sk)) {
        Ok(_sk) => { _sk },
        Err(_error) => return Err(SyntaxError::new(&format!("error while parsing msk string: {}", _error)).into()),
    };

    let sk_attributes: HashSet<_> = _sk._d_j.iter()
        .map(|_values| _values._str.to_string())
        .collect::<Vec<_>>().iter().cloned().collect();

    let mut attributes_subset_vec = Vec::new();
    for i in 0..attributes_subset.length() {

        if !attributes_subset.get(i).is_string() {
            return Err(TypeError::new(&format!("the given attribute subset contains non-string value at position {}", i)).into())
        }
        let _a = attributes_subset.get(i).as_string().unwrap();

        if !sk_attributes.contains(&_a) {
            return Err(Error::new(&format!("the given attribute set is not a subset of the given sk. \"{}\" is not an attribute of sk", &_a)))
        }
        attributes_subset_vec.push(_a);
    }

    match bsw::delegate(&_pk, &_sk, &attributes_subset_vec) {
        Some(sk) => Ok(serde_json::to_string(&sk).unwrap()),
        None => return Err(TypeError::new("attributes is_empty or len() == 0").into()),
    }
}