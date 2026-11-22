//! Reading cookies out of a Chromium-based browser (Chrome, Brave, Chromium,
//! Edge) and out of Firefox, on Linux, macOS and Windows.
//!
//! Chromium encrypts cookie values on disk, and how depends on the OS:
//!
//! * **Linux** — `v10`/`v11`: AES-128-CBC. The key is
//!   `PBKDF2-HMAC-SHA1(password, "saltysalt", 1 iteration)`, where the
//!   password comes from the keyring (`secret-tool`, needs a D-Bus session).
//! * **macOS** — `v10`: AES-128-CBC, same scheme but 1003 iterations, and the
//!   password comes from the Keychain (`security find-generic-password`).
//! * **Windows** — `v10`: AES-256-GCM. The key is in `Local State`
//!   (`os_crypt.encrypted_key`), protected with DPAPI, which we unwrap
//!   through PowerShell. `v20` (app-bound, Chrome 127+) cookies can only be
//!   read by Chrome itself and are skipped.
//!
//! Firefox stores cookies unencrypted on every OS.

use std::path::{Path, PathBuf};
use std::process::Command;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use rusqlite::Connection;

use crate::error::{Error, Result};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const SALT: &[u8] = b"saltysalt";
const IV: &[u8; 16] = b"                ";

#[derive(Debug, Clone)]
pub struct BrowserCookie {
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub name: String,
    pub value: String,
    pub expires: i64,
}

/// Where a browser keeps its profile data.
struct BrowserProfile {
    /// Directory holding `Local State` and the profile folders.
    root: PathBuf,
    /// Name of the keyring / Keychain entry that holds the password
    /// (Linux and macOS).
    keyring_app: String,
}

impl BrowserProfile {
    fn detect(browser: &str) -> Result<BrowserProfile> {
        let name = browser.to_ascii_lowercase();
        // (profile folder relative to the OS data directory, keyring entry)
        let (rel, keyring_app) = match (cfg!(windows), cfg!(target_os = "macos"), name.as_str()) {
            (true, _, "chrome") => ("Google/Chrome/User Data", "Chrome Safe Storage"),
            (true, _, "brave") => ("BraveSoftware/Brave-Browser/User Data", "Brave Safe Storage"),
            (true, _, "chromium") => ("Chromium/User Data", "Chromium Safe Storage"),
            (true, _, "edge") => ("Microsoft/Edge/User Data", "Edge Safe Storage"),
            (_, true, "chrome") => ("Google/Chrome", "Chrome Safe Storage"),
            (_, true, "brave") => ("BraveSoftware/Brave-Browser", "Brave Safe Storage"),
            (_, true, "chromium") => ("Chromium", "Chromium Safe Storage"),
            (_, true, "edge") => ("Microsoft Edge", "Microsoft Edge Safe Storage"),
            (_, _, "chrome") => ("google-chrome", "Chrome Safe Storage"),
            (_, _, "brave") => ("BraveSoftware/Brave-Browser", "Brave Safe Storage"),
            (_, _, "chromium") => ("chromium", "Chromium Safe Storage"),
            (_, _, "edge") => ("microsoft-edge", "Edge Safe Storage"),
            (_, _, other) => return Err(Error::other(format!("unknown browser `{other}`"))),
        };

        // %LOCALAPPDATA% on Windows, ~/Library/Application Support on macOS,
        // ~/.config on Linux.
        let base = if cfg!(windows) {
            dirs::data_local_dir()
        } else {
            dirs::config_dir()
        }
        .ok_or_else(|| Error::other("no application data directory"))?;

        let root = base.join(rel);
        if !root.exists() {
            return Err(Error::other(format!(
                "no {browser} profile found at {}",
                root.display()
            )));
        }
        Ok(BrowserProfile {
            root,
            keyring_app: keyring_app.to_string(),
        })
    }

    /// The `Cookies` database of the default profile.
    fn cookies_db(&self) -> Option<PathBuf> {
        let candidates = [
            self.root.join("Default").join("Network").join("Cookies"),
            self.root.join("Default").join("Cookies"),
        ];
        candidates.into_iter().find(|p| p.exists())
    }

    fn local_state(&self) -> Option<PathBuf> {
        let p = self.root.join("Local State");
        if p.exists() {
            Some(p)
        } else {
            None
        }
    }
}

/// The keys needed to decrypt a browser's cookies.
enum Keys {
    /// Linux and macOS: AES-128-CBC.
    Cbc {
        v10: [u8; 16],
        v11: Option<[u8; 16]>,
    },
    /// Windows: AES-256-GCM.
    Gcm([u8; 32]),
}

/// Ask the OS keyring (Linux) or Keychain (macOS) for the password.
fn keyring_password(app: &str) -> Result<Vec<u8>> {
    if cfg!(target_os = "macos") {
        let output = Command::new("security")
            .args(["find-generic-password", "-w", "-s", app])
            .output()
            .map_err(|e| Error::other(format!("cannot run `security` to reach the Keychain: {e}")))?;
        if !output.status.success() {
            return Err(Error::other(format!(
                "the Keychain has no entry for `{app}` (was access denied?)"
            )));
        }
        let mut pw = output.stdout;
        while pw.last() == Some(&b'\n') {
            pw.pop();
        }
        return Ok(pw);
    }

    let output = Command::new("secret-tool")
        .args(["lookup", "application", app])
        .output()
        .map_err(|e| {
            Error::other(format!(
                "cannot run secret-tool to reach the keyring ({e}); \
                 is a D-Bus session running?"
            ))
        })?;

    if !output.status.success() {
        return Err(Error::other(format!(
            "the keyring has no entry for `{app}` (is the browser unlocked?)"
        )));
    }
    Ok(output.stdout)
}

/// PBKDF2-HMAC-SHA1 — Chromium's (deliberately weak) KDF.
fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, &mut key);
    key
}

fn decrypt_v11(encrypted_key_b64: &str, password: &[u8]) -> Result<[u8; 16]> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encrypted_key_b64)
        .map_err(|e| Error::other(format!("bad encrypted_key in Local State: {e}")))?;
    let raw = raw.strip_prefix(b"DPAPI").unwrap_or(&raw);
    if raw.len() < 16 {
        return Err(Error::other("encrypted_key is too short"));
    }
    let mut buf = raw.to_vec();
    let mut key = [0u8; 16];
    // On Linux the keyring password is used directly as the AES key.
    let mut pwd = [0u8; 16];
    let take = password.len().min(16);
    pwd[..take].copy_from_slice(&password[..take]);
    let dec = Aes128CbcDec::new_from_slices(&pwd, IV)
        .map_err(|_| Error::other("bad key length"))?;
    let plain = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| Error::other("could not decrypt the browser key"))?;
    key.copy_from_slice(&plain[..16]);
    Ok(key)
}

/// The AES key for `v10` cookies on Linux (1 iteration) and macOS (1003).
fn v10_key(password: &[u8]) -> [u8; 16] {
    let iterations = if cfg!(target_os = "macos") { 1003 } else { 1 };
    pbkdf2_sha1(password, SALT, iterations)
}

/// Unwrap the DPAPI-protected AES key in `Local State` (Windows).
///
/// DPAPI has no safe-Rust binding in our dependency set, so PowerShell does
/// the call. The blob goes in as base64, so nothing can be injected.
fn windows_key(local_state: &Path) -> Result<[u8; 32]> {
    use base64::Engine;
    let b64 = read_local_state_key(local_state)
        .ok_or_else(|| Error::other("no os_crypt.encrypted_key in Local State"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| Error::other(format!("bad encrypted_key in Local State: {e}")))?;
    let blob = raw
        .strip_prefix(b"DPAPI")
        .ok_or_else(|| Error::other("the browser key is not DPAPI protected"))?;
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(blob);

    let script = format!(
        "Add-Type -AssemblyName System.Security; \
         $b=[Convert]::FromBase64String('{blob_b64}'); \
         [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect(\
         $b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser))"
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| Error::other(format!("cannot run PowerShell to unwrap the key: {e}")))?;
    if !output.status.success() {
        return Err(Error::other("DPAPI could not unwrap the browser key"));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let key = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|e| Error::other(format!("bad DPAPI output: {e}")))?;
    key.try_into()
        .map_err(|_| Error::other("the browser key has the wrong length"))
}

/// Why a value could not be decrypted.
enum Skip {
    /// `v20` app-bound encryption: only Chrome itself can read it.
    AppBound,
    Other,
}

/// Decrypt a single cookie value.
fn decrypt_value(encrypted: &[u8], host: &str, keys: &Keys) -> std::result::Result<Vec<u8>, Skip> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    if encrypted.starts_with(b"v20") {
        return Err(Skip::AppBound);
    }
    let body = encrypted.get(3..).ok_or(Skip::Other)?;
    let plain = match (keys, &encrypted[..3]) {
        (Keys::Cbc { v10, .. }, b"v10") => cbc_decrypt(body, v10)?,
        (Keys::Cbc { v11: Some(k), .. }, b"v11") => cbc_decrypt(body, k)?,
        (Keys::Gcm(key), b"v10") => gcm_decrypt(body, key)?,
        _ => return Err(Skip::Other),
    };
    Ok(strip_host_hash(plain, host))
}

fn cbc_decrypt(body: &[u8], key: &[u8; 16]) -> std::result::Result<Vec<u8>, Skip> {
    let mut buf = body.to_vec();
    let dec = Aes128CbcDec::new_from_slices(key, IV).map_err(|_| Skip::Other)?;
    dec.decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map(|p| p.to_vec())
        .map_err(|_| Skip::Other)
}

/// `nonce (12) || ciphertext || tag (16)`.
fn gcm_decrypt(body: &[u8], key: &[u8; 32]) -> std::result::Result<Vec<u8>, Skip> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    if body.len() < 12 + 16 {
        return Err(Skip::Other);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Skip::Other)?;
    cipher
        .decrypt(Nonce::from_slice(&body[..12]), &body[12..])
        .map_err(|_| Skip::Other)
}

/// Newer Chromium prepends SHA-256(host_key) to the plaintext value.
fn strip_host_hash(plain: Vec<u8>, host: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    if plain.len() >= 32 && plain[..32] == Sha256::digest(host.as_bytes())[..] {
        plain[32..].to_vec()
    } else {
        plain
    }
}

/// Read and decrypt every cookie of a Chromium browser.
pub fn chromium_cookies(browser: &str) -> Result<Vec<BrowserCookie>> {
    let profile = BrowserProfile::detect(browser)?;
    let db = profile
        .cookies_db()
        .ok_or_else(|| Error::other("no Cookies database found (browser never ran?)"))?;

    let keys = if cfg!(windows) {
        let local_state = profile
            .local_state()
            .ok_or_else(|| Error::other("no Local State file found"))?;
        Keys::Gcm(windows_key(&local_state)?)
    } else {
        let password = keyring_password(&profile.keyring_app)?;
        let v11 = match profile.local_state() {
            Some(path) => {
                read_local_state_key(&path).and_then(|b64| decrypt_v11(&b64, &password).ok())
            }
            None => None,
        };
        Keys::Cbc {
            v10: v10_key(&password),
            v11,
        }
    };

    // Chromium keeps the database locked while the browser runs; copy it.
    let tmp = tempdir_path();
    std::fs::copy(&db, &tmp).map_err(|e| {
        Error::other(format!(
            "cannot copy the cookie database ({e}); close {browser} completely and try again"
        ))
    })?;

    let conn = Connection::open(&tmp)?;
    let mut stmt = conn.prepare(
        "SELECT host_key, path, is_secure, name, value, encrypted_value, expires_utc
         FROM cookies",
    )?;

    let mut out = Vec::new();
    let mut app_bound = 0usize;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let host: String = row.get(0)?;
        let plain_value: String = row.get(4)?;
        let encrypted: Vec<u8> = row.get(5)?;
        let value = if plain_value.is_empty() && !encrypted.is_empty() {
            match decrypt_value(&encrypted, &host, &keys) {
                Ok(v) => String::from_utf8_lossy(&v).to_string(),
                Err(Skip::AppBound) => {
                    app_bound += 1;
                    continue;
                }
                Err(Skip::Other) => continue,
            }
        } else {
            plain_value
        };

        let expires_raw: i64 = row.get(6)?;
        out.push(BrowserCookie {
            domain: host,
            path: row.get(1)?,
            secure: row.get::<_, i64>(2)? != 0,
            name: row.get(3)?,
            value,
            expires: chromium_timestamp(expires_raw),
        });
    }
    drop(rows);
    drop(stmt);
    drop(conn);
    let _ = std::fs::remove_file(&tmp);

    if out.is_empty() && app_bound > 0 {
        return Err(Error::other(format!(
            "{browser} uses app-bound (v20) cookie encryption, which only the browser itself \
             can read. Export a cookies.txt with a browser extension and use --cookies, \
             or use --cookies-from-browser firefox"
        )));
    }
    if app_bound > 0 {
        eprintln!("note: skipped {app_bound} app-bound (v20) cookies that cannot be decrypted");
    }
    Ok(out)
}

/// Chromium stores microseconds since 1601-01-01. Convert to unix seconds.
fn chromium_timestamp(raw: i64) -> i64 {
    if raw == 0 {
        return 0;
    }
    // Microseconds since 1601-01-01 -> seconds since the unix epoch.
    let unix_micros = raw - 11_644_473_600_000_000;
    unix_micros / 1_000_000
}

fn read_local_state_key(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&content).ok()?;
    doc.get("os_crypt")?
        .get("encrypted_key")?
        .as_str()
        .map(str::to_string)
}

/// Firefox stores cookies in `cookies.sqlite` **unencrypted**.
pub fn firefox_cookies() -> Result<Vec<BrowserCookie>> {
    let root = if cfg!(windows) {
        dirs::data_dir().map(|d| d.join("Mozilla").join("Firefox").join("Profiles"))
    } else if cfg!(target_os = "macos") {
        dirs::data_dir().map(|d| d.join("Firefox").join("Profiles"))
    } else {
        dirs::home_dir().map(|d| d.join(".mozilla").join("firefox"))
    }
    .ok_or_else(|| Error::other("no home directory"))?;
    if !root.exists() {
        return Err(Error::other("no Firefox profile found"));
    }

    let mut profiles: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let path = entry.path();
        if path.join("cookies.sqlite").exists() {
            profiles.push(path);
        }
    }
    // The everyday profile is the one called `*.default-release`.
    profiles.sort_by_key(|p| {
        !p.file_name()
            .map(|n| n.to_string_lossy().ends_with("default-release"))
            .unwrap_or(false)
    });
    let profile = profiles
        .into_iter()
        .next()
        .ok_or_else(|| Error::other("no Firefox profile with cookies.sqlite"))?;

    let tmp = tempdir_path();
    std::fs::copy(profile.join("cookies.sqlite"), &tmp)?;

    let conn = Connection::open(&tmp)?;
    let mut stmt = conn.prepare(
        "SELECT host, path, isSecure, name, value, expiry FROM moz_cookies",
    )?;
    let mut out = Vec::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        out.push(BrowserCookie {
            domain: row.get(0)?,
            path: row.get(1)?,
            secure: row.get::<_, i64>(2)? != 0,
            name: row.get(3)?,
            value: row.get(4)?,
            expires: row.get(5)?,
        });
    }
    let _ = std::fs::remove_file(&tmp);
    Ok(out)
}

/// Read cookies from any supported browser.
pub fn extract(browser: &str) -> Result<Vec<BrowserCookie>> {
    if browser.eq_ignore_ascii_case("firefox") {
        firefox_cookies()
    } else {
        chromium_cookies(browser)
    }
}

/// Build a cookie jar from browser cookies.
pub fn to_jar(cookies: &[BrowserCookie]) -> reqwest::cookie::Jar {
    let jar = reqwest::cookie::Jar::default();
    for c in cookies {
        let host = c.domain.trim_start_matches('.');
        if host.is_empty() {
            continue;
        }
        let url = match reqwest::Url::parse(&format!("https://{host}{}", c.path)) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let mut parts = vec![format!("{}={}", c.name, c.value)];
        parts.push(format!("Domain={}", c.domain));
        parts.push(format!("Path={}", c.path));
        if c.secure {
            parts.push("Secure".into());
        }
        if c.expires > 0 {
            parts.push(format!("Expires={}", c.expires));
        }
        jar.add_cookie_str(&parts.join("; "), &url);
    }
    jar
}

fn tempdir_path() -> PathBuf {
    let dir = std::env::temp_dir();
    let name = format!(
        "ytgrab-cookies-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    dir.join(name)
}

/// Turn browser cookies into a Netscape cookie file.
pub fn to_netscape(cookies: &[BrowserCookie]) -> String {
    let mut out = String::from("# Netscape HTTP Cookie File\n");
    for c in cookies {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            c.domain,
            if c.secure { "TRUE" } else { "FALSE" },
            c.path,
            if c.secure { "TRUE" } else { "FALSE" },
            c.expires,
            c.name,
            c.value
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_timestamp_conversion() {
        // 1601-01-01 -> 1970-01-01
        assert_eq!(chromium_timestamp(11_644_473_600_000_000), 0);
        // 2024-01-01T00:00:00Z
        assert_eq!(chromium_timestamp(13_348_540_800_000_000), 1_704_067_200);
    }

    #[test]
    fn netscape_output_has_the_right_shape() {
        let cookies = vec![BrowserCookie {
            domain: ".youtube.com".into(),
            path: "/".into(),
            secure: true,
            name: "SID".into(),
            value: "abc".into(),
            expires: 1_700_000_000,
        }];
        let text = to_netscape(&cookies);
        assert!(text.contains(".youtube.com\tTRUE\t/\tTRUE\t1700000000\tSID\tabc"));
    }

    #[test]
    fn v10_round_trip() {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

        let key = v10_key(b"hunter2");
        let plaintext = b"cookie-value-1234";

        // Chromium stores "v10" + AES(value); the prefix is not encrypted.
        let mut buf = vec![0u8; 32];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let enc = Aes128CbcEnc::new_from_slices(&key, IV).unwrap();
        let cipher = enc.encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len()).unwrap();

        let mut stored = b"v10".to_vec();
        stored.extend_from_slice(cipher);

        let keys = Keys::Cbc { v10: key, v11: None };
        let out = decrypt_value(&stored, ".youtube.com", &keys).ok().unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn gcm_round_trip_with_host_hash() {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use sha2::{Digest, Sha256};

        let key = [7u8; 32];
        let host = ".youtube.com";
        let mut plain = Sha256::digest(host.as_bytes()).to_vec();
        plain.extend_from_slice(b"secret");

        let nonce = [1u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), plain.as_slice()).unwrap();

        let mut stored = b"v10".to_vec();
        stored.extend_from_slice(&nonce);
        stored.extend_from_slice(&ct);

        let out = decrypt_value(&stored, host, &Keys::Gcm(key)).ok().unwrap();
        assert_eq!(out, b"secret");
    }

    #[test]
    fn app_bound_cookies_are_reported() {
        let keys = Keys::Gcm([0u8; 32]);
        assert!(matches!(
            decrypt_value(b"v20abcdef", ".x.com", &keys),
            Err(Skip::AppBound)
        ));
    }
}
