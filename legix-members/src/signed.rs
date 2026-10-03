use crate::Error;

const ARMOR_BEGIN: &[u8] = b"-----BEGIN SSH SIGNATURE-----\n";
const ARMOR_END: &[u8] = b"-----END SSH SIGNATURE-----\n";

/// Split signed text from its signature, which must be one armored block, at the start of a line, ending the bytes.
pub(crate) fn split(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let at = bytes
        .windows(ARMOR_BEGIN.len())
        .position(|window| window == ARMOR_BEGIN)
        .ok_or(Error::Format("no signature"))?;
    let signature = &bytes[at..];
    if (at > 0 && bytes[at - 1] != b'\n')
        || !signature.ends_with(ARMOR_END)
        || signature[ARMOR_BEGIN.len()..]
            .windows(ARMOR_BEGIN.len())
            .any(|window| window == ARMOR_BEGIN)
    {
        return Err(Error::Format("the text does not end with one armored signature"));
    }
    Ok((&bytes[..at], signature))
}
