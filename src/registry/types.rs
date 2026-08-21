use serde::Deserialize;
use url::Url;

/// Types in this module correspond to the API responses from hashicorp,
/// which can be found at
/// https://developer.hashicorp.com/terraform/internals/provider-registry-protocol

// Terraform registry provider API response for "List Available Versions"

#[derive(Deserialize, Debug)]
pub struct ProviderVersions {
    pub versions: Vec<ProviderVersionItem>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct ProviderVersionItem {
    pub version: String,
    pub protocols: Vec<String>,
    pub platforms: Vec<ProviderPlatform>,
}

#[derive(Deserialize, Debug)]
pub struct ProviderPlatform {
    pub os: String,
    pub arch: String,
}

// Terraform registry provider API response for "Find a provider package"

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ProviderResponse {
    pub protocols: Vec<String>,
    pub os: String,
    pub arch: String,
    pub filename: String,
    pub download_url: Url,
    pub shasums_url: Url,
    pub shasums_signature_url: Url,
    pub shasum: String,
    pub signing_keys: ProviderSigningKeys,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct ProviderSigningKeys {
    pub gpg_public_keys: Option<Vec<ProviderGPGPublicKey>>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct ProviderGPGPublicKey {
    pub key_id: String,
    pub ascii_armor: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn provider_response_with_gpg_public_keys(gpg_public_keys: Option<Value>) -> ProviderResponse {
        let mut signing_keys = json!({});
        if let Some(gpg_public_keys) = gpg_public_keys {
            signing_keys["gpg_public_keys"] = gpg_public_keys;
        }

        serde_json::from_value(json!({
            "protocols": ["5.0"],
            "os": "darwin",
            "arch": "arm64",
            "filename": "terraform-provider-mysql_3.0.94_darwin_arm64.zip",
            "download_url": "https://example.com/terraform-provider-mysql.zip",
            "shasums_url": "https://example.com/terraform-provider-mysql_SHA256SUMS",
            "shasums_signature_url": "https://example.com/terraform-provider-mysql_SHA256SUMS.sig",
            "shasum": "43e84dcf457cc73db97ff491719a0adf6097653804393d1bdf0354a3a9418fa0",
            "signing_keys": signing_keys
        }))
        .expect("provider response should deserialize")
    }

    #[test]
    fn provider_response_accepts_null_gpg_public_keys() {
        let response = provider_response_with_gpg_public_keys(Some(Value::Null));

        assert!(response.signing_keys.gpg_public_keys.is_none());
    }

    #[test]
    fn provider_response_accepts_missing_gpg_public_keys() {
        let response = provider_response_with_gpg_public_keys(None);

        assert!(response.signing_keys.gpg_public_keys.is_none());
    }

    #[test]
    fn provider_response_preserves_empty_gpg_public_keys() {
        let response = provider_response_with_gpg_public_keys(Some(json!([])));

        assert!(response
            .signing_keys
            .gpg_public_keys
            .expect("empty key list should be present")
            .is_empty());
    }

    #[test]
    fn provider_response_preserves_populated_gpg_public_keys() {
        let response = provider_response_with_gpg_public_keys(Some(json!([{
            "key_id": "0123456789ABCDEF",
            "ascii_armor": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nexample\n-----END PGP PUBLIC KEY BLOCK-----"
        }])));
        let keys = response
            .signing_keys
            .gpg_public_keys
            .expect("populated key list should be present");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "0123456789ABCDEF");
        assert_eq!(
            keys[0].ascii_armor,
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nexample\n-----END PGP PUBLIC KEY BLOCK-----"
        );
    }
}
