//! git's allowed-signers file (`gpg.ssh.allowedSignersFile`), in the format of `ssh-keygen(1)`, ALLOWED SIGNERS:
//!
//! ```text
//! # principals            options                                   key
//! ada@example.com                                                   ssh-ed25519 AAAA…
//! *@example.com,!ex@example.com namespaces="git",valid-after="20260101Z" ssh-ed25519 AAAA…
//! ```
//!
//! Principals and namespaces are comma-separated patterns with `*` and `?` wildcards and `!` negation. Times are
//! `YYYYMMDD`, `YYYYMMDDHHMM` or `YYYYMMDDHHMMSS`; with a trailing `Z` they are UTC, otherwise local time.

use std::fmt;

use ssh_key::PublicKey;

use crate::{Error, NAMESPACE, Trust};

/// One line of an allowed-signers file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Comma-separated principal patterns, as written.
    pub principals: String,
    /// The key.
    pub key: PublicKey,
    /// `namespaces="…"`: the namespaces the key may sign in, as patterns; `None` means any.
    pub namespaces: Option<String>,
    /// `valid-after="…"`: the Unix time from which the key may sign.
    pub valid_after: Option<i64>,
    /// `valid-before="…"`: the Unix time until which the key may sign.
    pub valid_before: Option<i64>,
    /// `cert-authority`: the key certifies other keys. Certificates are not supported, so such an entry never
    /// matches a signature.
    pub cert_authority: bool,
}

impl Entry {
    /// An entry that lets `key` sign for `principals` in any namespace, at any time.
    pub fn new(principals: impl Into<String>, key: PublicKey) -> Self {
        Entry {
            principals: principals.into(),
            key,
            namespaces: None,
            valid_after: None,
            valid_before: None,
            cert_authority: false,
        }
    }

    fn signs_with(&self, key: &PublicKey) -> bool {
        !self.cert_authority
            && self.key.key_data() == key.key_data()
            && self
                .namespaces
                .as_deref()
                .is_none_or(|namespaces| pattern_list_matches(NAMESPACE, namespaces))
    }

    fn valid_at(&self, time: Option<i64>) -> bool {
        let Some(time) = time else { return true };
        self.valid_after.is_none_or(|after| time >= after) && self.valid_before.is_none_or(|before| time <= before)
    }
}

/// The keys allowed to sign, and for whom.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AllowedSigners {
    entries: Vec<Entry>,
}

impl AllowedSigners {
    /// Read an allowed-signers file. Empty lines and `#` comments are skipped; any other line that cannot be read
    /// is an error, so that a typo never silently drops or widens trust.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut entries = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            entries.push(parse_line(line).map_err(|message| Error::AllowedSigners {
                line: number + 1,
                message,
            })?);
        }
        Ok(AllowedSigners { entries })
    }

    /// Allow `key` to sign for `principals` (comma-separated patterns) in any namespace, at any time.
    pub fn push(&mut self, principals: impl Into<String>, key: PublicKey) {
        self.entries.push(Entry::new(principals, key));
    }

    /// Add an entry with all its options.
    pub fn push_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    /// All entries, in file order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The principals `key` may sign for in the `git` namespace at `time` (Unix seconds; `None` ignores validity),
    /// from the first matching entry — what git reports after `ssh-keygen -Y find-principals`.
    pub fn principals_for(&self, key: &PublicKey, time: Option<i64>) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.signs_with(key) && entry.valid_at(time))
            .map(|entry| entry.principals.as_str())
    }

    /// Whether `principal` may sign with `key` in the `git` namespace at `time`, as `ssh-keygen -Y verify -I`
    /// decides it.
    pub fn allows(&self, principal: &str, key: &PublicKey, time: Option<i64>) -> bool {
        self.entries.iter().any(|entry| {
            entry.signs_with(key) && entry.valid_at(time) && pattern_list_matches(principal, &entry.principals)
        })
    }

    pub(crate) fn trust(&self, key: &PublicKey, time: Option<i64>) -> Trust {
        if let Some(principals) = self.principals_for(key, time) {
            return Trust::Allowed {
                principals: principals.into(),
            };
        }
        match self.entries.iter().find(|entry| entry.signs_with(key)) {
            Some(entry) => Trust::OutsideValidity {
                principals: entry.principals.clone(),
            },
            None => Trust::UnknownKey,
        }
    }
}

/// Writes the entries back in the allowed-signers format; times are written in UTC.
impl fmt::Display for AllowedSigners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for entry in &self.entries {
            let mut options = Vec::new();
            if entry.cert_authority {
                options.push("cert-authority".to_string());
            }
            if let Some(namespaces) = &entry.namespaces {
                options.push(format!("namespaces=\"{namespaces}\""));
            }
            if let Some(after) = entry.valid_after {
                options.push(format!("valid-after=\"{}\"", format_time(after)?));
            }
            if let Some(before) = entry.valid_before {
                options.push(format!("valid-before=\"{}\"", format_time(before)?));
            }
            let key = entry.key.to_openssh().map_err(|_| fmt::Error)?;
            if options.is_empty() {
                writeln!(f, "{} {key}", entry.principals)?;
            } else {
                writeln!(f, "{} {} {key}", entry.principals, options.join(","))?;
            }
        }
        Ok(())
    }
}

fn parse_line(line: &str) -> Result<Entry, String> {
    let (principals, rest) = token(line)?;
    if principals.is_empty() {
        return Err("no principals".into());
    }
    let rest = rest.trim_start();
    let (options, key) = if is_key_type(rest) {
        ("", rest)
    } else {
        let (options, key) = token(rest)?;
        (options, key.trim_start())
    };
    let key = PublicKey::from_openssh(key).map_err(|err| format!("the key cannot be read: {err}"))?;
    let mut entry = Entry::new(principals.trim_matches('"'), key);
    for option in split_options(options) {
        let (name, value) = match option.split_once('=') {
            Some((name, value)) => (name, Some(value.trim_matches('"'))),
            None => (option, None),
        };
        match (name.to_ascii_lowercase().as_str(), value) {
            ("cert-authority", None) => entry.cert_authority = true,
            ("namespaces", Some(value)) => entry.namespaces = Some(value.into()),
            ("valid-after", Some(value)) => entry.valid_after = Some(parse_time(value)?),
            ("valid-before", Some(value)) => entry.valid_before = Some(parse_time(value)?),
            _ => return Err(format!("unknown option {option:?}")),
        }
    }
    Ok(entry)
}

fn is_key_type(text: &str) -> bool {
    ["ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-sha2-", "rsa-sha2-"]
        .iter()
        .any(|prefix| text.starts_with(prefix))
}

/// The leading token of `text` up to unquoted whitespace, and the rest.
fn token(text: &str) -> Result<(&str, &str), String> {
    let mut quoted = false;
    for (index, char) in text.char_indices() {
        match char {
            '"' => quoted = !quoted,
            char if char.is_whitespace() && !quoted => return Ok((&text[..index], &text[index..])),
            _ => {}
        }
    }
    if quoted {
        Err("an unterminated quote".into())
    } else {
        Ok((text, ""))
    }
}

/// `options` split at commas outside quotes.
fn split_options(options: &str) -> impl Iterator<Item = &str> {
    let mut parts = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (index, char) in options.char_indices() {
        match char {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(&options[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&options[start..]);
    parts.into_iter().filter(|part| !part.is_empty())
}

fn parse_time(value: &str) -> Result<i64, String> {
    let (digits, utc) = match value.strip_suffix(['Z', 'z']) {
        Some(digits) => (digits, true),
        None => (value, false),
    };
    let invalid = || format!("invalid time {value:?}");
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let number = |range: std::ops::Range<usize>| digits[range].parse::<i16>().map_err(|_| invalid());
    let (hour, minute, second) = match digits.len() {
        8 => (0, 0, 0),
        12 => (number(8..10)?, number(10..12)?, 0),
        14 => (number(8..10)?, number(10..12)?, number(12..14)?),
        _ => return Err(invalid()),
    };
    let date_time = jiff::civil::DateTime::new(
        number(0..4)?,
        number(4..6)? as i8,
        number(6..8)? as i8,
        hour as i8,
        minute as i8,
        second as i8,
        0,
    )
    .map_err(|_| invalid())?;
    let zone = if utc {
        jiff::tz::TimeZone::UTC
    } else {
        jiff::tz::TimeZone::system()
    };
    Ok(date_time.to_zoned(zone).map_err(|_| invalid())?.timestamp().as_second())
}

fn format_time(seconds: i64) -> Result<String, fmt::Error> {
    let time = jiff::Timestamp::from_second(seconds).map_err(|_| fmt::Error)?;
    Ok(time.strftime("%Y%m%d%H%M%SZ").to_string())
}

/// OpenSSH's `match_pattern_list()`: a match of any pattern, unless a negated (`!`) pattern matches.
fn pattern_list_matches(value: &str, patterns: &str) -> bool {
    let mut matched = false;
    for pattern in patterns.split(',') {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(pattern) => (true, pattern),
            None => (false, pattern),
        };
        if wildcard_matches(value.as_bytes(), pattern.as_bytes()) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// `*` matches any run of bytes, `?` any single byte.
fn wildcard_matches(value: &[u8], pattern: &[u8]) -> bool {
    let (mut v, mut p) = (0, 0);
    let mut backtrack = None;
    while v < value.len() {
        match pattern.get(p) {
            Some(b'*') => {
                backtrack = Some((p, v));
                p += 1;
            }
            Some(&byte) if byte == b'?' || byte == value[v] => {
                v += 1;
                p += 1;
            }
            _ => match backtrack {
                Some((star, at)) => {
                    p = star + 1;
                    v = at + 1;
                    backtrack = Some((star, at + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

#[cfg(test)]
mod tests {
    use super::{pattern_list_matches, wildcard_matches};

    #[test]
    fn wildcards_and_negation_follow_openssh() {
        assert!(wildcard_matches(b"ada@example.com", b"*@example.com"));
        assert!(wildcard_matches(b"ada@example.com", b"ad?@example.*"));
        assert!(!wildcard_matches(b"ada@example.org", b"*@example.com"));
        assert!(wildcard_matches(b"", b"*"));
        assert!(pattern_list_matches("ada@example.com", "bob@example.com,*@example.com"));
        assert!(!pattern_list_matches("ex@example.com", "*@example.com,!ex@example.com"));
        assert!(!pattern_list_matches("git", "file"));
    }
}
