//! Frames: how a sync travels on one QUIC stream in each direction.

use std::io::{Read, Seek, SeekFrom, Write};

use iroh::endpoint::{RecvStream, SendStream};
use legix_crypt::Oid;

use crate::{Error, error::connection_error};

pub(crate) const HELLO: u8 = 1;
pub(crate) const INVENTORY: u8 = 2;
pub(crate) const ENTRY: u8 = 3;
pub(crate) const ENDPOINT: u8 = 4;
pub(crate) const JOIN: u8 = 5;
pub(crate) const HEAD: u8 = 6;
pub(crate) const OBJECT: u8 = 7;
pub(crate) const CHUNK: u8 = 8;
pub(crate) const OBJECT_END: u8 = 9;
pub(crate) const ENVELOPE: u8 = 10;
pub(crate) const END: u8 = 11;
pub(crate) const DONE: u8 = 12;

/// The most bytes of an object one chunk carries.
pub(crate) const CHUNK_LEN: usize = 1 << 20;

/// The longest payload a frame of `kind` may have, or `None` for a kind that does not exist.
fn max_len(kind: u8) -> Option<u64> {
    let kib = |n: u64| n << 10;
    Some(match kind {
        HELLO | ENDPOINT | JOIN => 32 + kib(64),
        INVENTORY => 256 << 20,
        ENTRY => 8 + legix_members::MAX_LEN as u64,
        HEAD => 32 + 8 + kib(64),
        OBJECT => 32,
        CHUNK => CHUNK_LEN as u64,
        ENVELOPE => 32 + kib(1),
        OBJECT_END | END | DONE => 0,
        _ => return None,
    })
}

/// Write a frame: its kind, the length of its payload as 8 bytes big-endian, and the payload, given in parts.
pub(crate) async fn write(stream: &mut SendStream, kind: u8, parts: &[&[u8]]) -> Result<(), Error> {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    let mut header = [0; 9];
    header[0] = kind;
    header[1..].copy_from_slice(&(len as u64).to_be_bytes());
    stream.write_all(&header).await.map_err(connection_error)?;
    for part in parts {
        stream.write_all(part).await.map_err(connection_error)?;
    }
    Ok(())
}

/// Read a frame: its kind and its payload. A frame longer than its kind allows is refused before it is read.
pub(crate) async fn read(stream: &mut RecvStream) -> Result<(u8, Vec<u8>), Error> {
    let mut header = [0; 9];
    stream.read_exact(&mut header).await.map_err(connection_error)?;
    let kind = header[0];
    let len = u64::from_be_bytes(header[1..].try_into().expect("8 bytes"));
    let max = max_len(kind).ok_or(Error::Protocol("a frame of an unknown kind"))?;
    if len > max {
        return Err(Error::Protocol("a frame longer than its kind allows"));
    }
    let mut payload = vec![0; usize::try_from(len).map_err(|_| Error::Protocol("a frame too long"))?];
    stream.read_exact(&mut payload).await.map_err(connection_error)?;
    Ok((kind, payload))
}

/// Send an object: a frame with its id, its bytes in chunks, and a frame that ends it.
pub(crate) async fn write_object(
    stream: &mut SendStream,
    oid: &Oid,
    object: &mut (dyn Read + Send),
) -> Result<(), Error> {
    write(stream, OBJECT, &[oid.as_bytes()]).await?;
    let mut buf = vec![0; CHUNK_LEN];
    loop {
        let n = object.read(&mut buf)?;
        if n == 0 {
            break;
        }
        write(stream, CHUNK, &[&buf[..n]]).await?;
    }
    write(stream, OBJECT_END, &[]).await
}

/// Read the chunks of an object, after the frame with its id, into a temporary file.
pub(crate) async fn read_object(stream: &mut RecvStream) -> Result<std::fs::File, Error> {
    let mut file = tempfile::tempfile()?;
    loop {
        match read(stream).await? {
            (CHUNK, chunk) => file.write_all(&chunk)?,
            (OBJECT_END, _) => break,
            _ => return Err(Error::Protocol("an object's chunks are interrupted")),
        }
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}
