//! Server data models. All fields that the server encrypts stay as EncString
//! *strings* here; decryption happens on demand in [`crate::vault`].
//!
//! Parsing is deliberately lenient: unknown fields are ignored, unknown cipher
//! types are kept as raw integers, and key casing is normalised first so both
//! PascalCase (older official servers) and camelCase (Vaultwarden, new servers)
//! responses deserialize into the same structs.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Lower-case the first character of every object key, recursively.
pub fn normalize_keys(v: Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| {
                    let mut c = k.chars();
                    let nk = match c.next() {
                        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
                        None => String::new(),
                    };
                    (nk, normalize_keys(v))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(normalize_keys).collect()),
        other => other,
    }
}

pub const CIPHER_TYPE_LOGIN: i64 = 1;
pub const CIPHER_TYPE_SECURE_NOTE: i64 = 2;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    #[serde(default)]
    pub profile: Profile,
    #[serde(default)]
    pub ciphers: Vec<Cipher>,
    #[serde(default)]
    pub folders: Vec<Folder>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub email: String,
    /// Protected user key (EncString type 2 under the stretched master key).
    #[serde(default)]
    pub key: Option<String>,
    /// EncString of the PKCS#8 RSA private key under the user key.
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub organizations: Vec<ProfileOrganization>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileOrganization {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Org symmetric key wrapped with the user's RSA public key (type 4).
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    /// Raw type: 1 login, 2 secure note, 3 card, 4 identity, 5 ssh key, ...
    #[serde(rename = "type", default)]
    pub kind: i64,
    #[serde(default)]
    pub organization_id: Option<String>,
    /// Per-cipher key (EncString under user or org key).
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub login: Option<Login>,
    #[serde(default)]
    pub deleted_date: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub uris: Option<Vec<LoginUri>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    #[serde(default)]
    pub uri: Option<String>,
}

impl SyncResponse {
    pub fn from_json(v: Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(normalize_keys(v))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: i64,
    pub kdf_iterations: i64,
    #[serde(default)]
    pub kdf_memory: Option<i64>,
    #[serde(default)]
    pub kdf_parallelism: Option<i64>,
}

/// Successful `/connect/token` response (keys normalised).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "expires_in", default)]
    pub expires_in: Option<i64>,
    #[serde(rename = "refresh_token", default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub kdf: Option<i64>,
    #[serde(default)]
    pub kdf_iterations: Option<i64>,
    #[serde(default)]
    pub kdf_memory: Option<i64>,
    #[serde(default)]
    pub kdf_parallelism: Option<i64>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenResponse(<redacted>)")
    }
}

/// Error body from `/connect/token`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenError {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(rename = "error_description", default)]
    pub error_description: Option<String>,
    #[serde(default)]
    pub two_factor_providers: Option<Vec<Value>>,
    #[serde(default)]
    pub error_model: Option<ErrorModel>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorModel {
    #[serde(default)]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pascal_and_camel_parse_the_same() {
        let pascal = json!({"Profile": {"Id": "u", "Email": "a@b", "Key": "2.x|y|z", "Organizations": []},
            "Ciphers": [{"Id": "c1", "Type": 1, "Name": "2.a|b|c", "Login": {"Username": "2.d|e|f", "Uris": [{"Uri": "2.g|h|i", "Match": null}]}}]});
        let camel = json!({"profile": {"id": "u", "email": "a@b", "key": "2.x|y|z", "organizations": []},
            "ciphers": [{"id": "c1", "type": 1, "name": "2.a|b|c", "login": {"username": "2.d|e|f", "uris": [{"uri": "2.g|h|i"}]}}]});
        let a = SyncResponse::from_json(pascal).unwrap();
        let b = SyncResponse::from_json(camel).unwrap();
        assert_eq!(
            a.ciphers[0].login.as_ref().unwrap().username,
            b.ciphers[0].login.as_ref().unwrap().username
        );
        assert_eq!(a.profile.key, b.profile.key);
    }

    #[test]
    fn unknown_fields_and_types_are_tolerated() {
        let v = json!({"profile": {"id": "u", "brandNewField": {"x": 1}}, "ciphers": [
            {"id": "c", "type": 42, "fido2Credentials": [1,2,3], "sshKey": {"privateKey": "2.a|b|c"}},
            {"id": "d", "type": 5}],
            "sends": [{"id": "s"}], "policies": null, "somethingElse": true});
        let s = SyncResponse::from_json(v).unwrap();
        assert_eq!(s.ciphers.len(), 2);
        assert_eq!(s.ciphers[0].kind, 42);
    }

    #[test]
    fn token_response_debug_redacted() {
        let t: TokenResponse =
            serde_json::from_value(json!({"access_token": "SECRET", "refresh_token": "R"}))
                .unwrap();
        assert!(!format!("{t:?}").contains("SECRET"));
    }
}
