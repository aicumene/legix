use std::{fmt, str::FromStr};

use crate::{Error, Oid, object};

/// What a repository stores in a document's place: the id of the encrypted object and the document's length.
///
/// The text form is three lines, each ending in a line feed:
///
/// ```text
/// version legix-crypt/1
/// oid blake3:<64 lowercase hex digits>
/// size <the document's length in bytes>
/// ```
///
/// A commit that holds a pointer commits to exactly one document: the id names exactly one object, and an object opens
/// under exactly one key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Pointer {
    /// The id of the encrypted object.
    pub oid: Oid,
    /// The length of the document in bytes.
    pub size: u64,
}

impl Pointer {
    /// The version this crate writes and reads.
    pub const VERSION: &'static str = "legix-crypt/1";

    /// The longest a pointer can be, which tells pointers from documents without reading large files.
    pub const MAX_LEN: usize = 124;

    /// Read a pointer from its text form. Anything else — another version, other lines, a carriage return, digits in
    /// upper case, a size with leading zeros — is refused, so a pointer has exactly one text form.
    pub fn parse(text: &[u8]) -> Result<Self, Error> {
        if text.len() > Self::MAX_LEN {
            return Err(Error::Pointer("longer than a pointer can be"));
        }
        let text = std::str::from_utf8(text).map_err(|_| Error::Pointer("not UTF-8"))?;
        let text = text
            .strip_suffix('\n')
            .ok_or(Error::Pointer("the last line does not end with a line feed"))?;
        let mut lines = text.split('\n');
        let (Some(version), Some(oid), Some(size), None) = (lines.next(), lines.next(), lines.next(), lines.next())
        else {
            return Err(Error::Pointer("expected three lines: version, oid and size"));
        };
        if version
            .strip_prefix("version ")
            .ok_or(Error::Pointer("the first line is not `version …`"))?
            != Self::VERSION
        {
            return Err(Error::Pointer("a version this crate does not read"));
        }
        let oid = oid
            .strip_prefix("oid ")
            .ok_or(Error::Pointer("the second line is not `oid …`"))?
            .parse()?;
        let size = size
            .strip_prefix("size ")
            .ok_or(Error::Pointer("the third line is not `size …`"))?;
        if size.is_empty() || !size.bytes().all(|b| b.is_ascii_digit()) || (size.len() > 1 && size.starts_with('0')) {
            return Err(Error::Pointer("the size is not a decimal number without leading zeros"));
        }
        let size = size.parse().map_err(|_| Error::Pointer("the size is too large"))?;
        if object::sealed_len(size).is_none() {
            return Err(Error::Pointer("the size is too large"));
        }
        Ok(Pointer { oid, size })
    }

    /// Whether `text` is a pointer this crate reads.
    pub fn is_pointer(text: &[u8]) -> bool {
        Self::parse(text).is_ok()
    }

    /// The length of the object the pointer names, or `None` if its size is too large for any object.
    pub fn object_len(&self) -> Option<u64> {
        object::sealed_len(self.size)
    }
}

impl fmt::Display for Pointer {
    /// The text form, as a repository stores it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "version {}\noid {}\nsize {}\n", Self::VERSION, self.oid, self.size)
    }
}

impl FromStr for Pointer {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text.as_bytes())
    }
}
