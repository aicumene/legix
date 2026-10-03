const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex digits.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
    hex
}

/// Read lowercase hex digits that fill `out` exactly.
pub(crate) fn decode(hex: &str, out: &mut [u8]) -> Option<()> {
    let hex = hex.as_bytes();
    if hex.len() != out.len() * 2 {
        return None;
    }
    for (byte, [high, low]) in out.iter_mut().zip(hex.as_chunks::<2>().0) {
        *byte = (digit(*high)? << 4) | digit(*low)?;
    }
    Some(())
}

fn digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// A decimal number without a sign or leading zeros.
pub(crate) fn number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// Read lowercase hex digits of any even length.
pub(crate) fn decode_vec(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = vec![0; hex.len() / 2];
    decode(hex, &mut out)?;
    Some(out)
}
