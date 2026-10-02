# legix-crypt formats, version 1

This document specifies, byte by byte, the formats `legix-crypt` writes. Another implementation that follows it reads
and writes the same bytes. The test vectors at the end come out of `legix-crypt` and out of an independent
implementation on OpenSSL.

There are four formats:

- **the object** — a document encrypted under its key;
- **the object id** — the name of an object;
- **the pointer** — what a repository stores in a document's place;
- **the key file** — a document key wrapped for a directory key store.

A version, once released, stays readable by every later release. A new version gets a new magic or version string; a
reader refuses versions it does not know.

## Primitives

- **ChaCha20-Poly1305**: the AEAD of [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), 32-byte key, 12-byte nonce,
  16-byte tag appended to the ciphertext.
- **XChaCha20-Poly1305**: the same with a 24-byte nonce, as in
  [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03).
- **HKDF-SHA-256**: [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) with SHA-256. `HKDF(ikm, salt, info)` below
  means extract with `salt` and `ikm`, then expand with `info` to 32 bytes.
- **BLAKE3**: the [BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs) hash with its default 32-byte output.

Strings are ASCII. `||` is concatenation. Integers are unsigned and big-endian.

## Document key

A document key is 32 bytes from a cryptographically secure random number generator. Each object is encrypted under a key
of its own, and a key encrypts one object only. Keys are never stored in the repository.

## Object

```
object  = header || payload
header  = magic || salt || commitment
magic   = "legix-crypt/1\n"                                   14 bytes
salt    = 16 random bytes, new for every object
commitment = HKDF(key, salt, "legix-crypt/1 commitment")      32 bytes
```

The header is 62 bytes. The payload key is

```
payload_key = HKDF(key, salt, "legix-crypt/1 payload")
```

The document is split into chunks of 65536 bytes; the last chunk holds the rest and is shorter or of the same length.
A document of length 0 has one chunk, of length 0. The last chunk is empty only in that case: a document whose length is a
multiple of 65536 ends with a full chunk, not with an empty one. Chunk `i`, counting from 0, is

```
nonce_i = i as 11 bytes || last_i                             12 bytes
last_i  = 0x01 for the last chunk, 0x00 for every other one
chunk_i = ChaCha20-Poly1305-Encrypt(payload_key, nonce_i, plaintext_i, associated data = empty)
                                                              plaintext length + 16 bytes
```

and the payload is `chunk_0 || chunk_1 || … || chunk_n-1`.

An object for a document of `L` bytes is `62 + L + 16 × max(1, ⌈L / 65536⌉)` bytes long.

### Opening an object

A reader:

1. refuses an object that is shorter than 62 bytes or does not start with the magic;
2. derives the commitment from the key and the salt and compares it with the header's in constant time; if they
   differ, the key is the wrong one and nothing is decrypted;
3. reads the payload in chunks of 65552 bytes (65536 + 16). A chunk is the last one exactly when the object ends after
   it, and it is decrypted with `last_i = 0x01`; every other chunk with `0x00`;
4. refuses a chunk shorter than 16 bytes, an empty last chunk that is not the only chunk, and any chunk that fails
   authentication.

Changing any byte, cutting the object short, extending it, or reordering its chunks makes the object fail at step 2 or
at step 4. A reader may hand out the plaintext of a chunk once the chunk is authenticated; if a later step fails, what
was handed out is incomplete and must be discarded.

The commitment makes the object open under one key only. Without it, an object could be built to authenticate under two
different keys and to show two different documents.

## Object id

```
oid       = BLAKE3(object)                                    32 bytes
oid text  = "blake3:" || 64 lowercase hex digits
```

The id is the hash of the encrypted bytes. Anyone can check an object against its id without the key, and the id tells
nothing about the document. The same document encrypted twice gives two objects with two ids.

## Pointer

A pointer is UTF-8 text of exactly three lines, each ending in a line feed (0x0a), in this order:

```
version legix-crypt/1
oid blake3:<64 lowercase hex digits>
size <the document's length in bytes>
```

- The size is a decimal number without a sign or leading zeros (`0` for an empty document). The object length it implies
  must fit in 64 bits.
- Nothing else is allowed: no carriage returns, no other lines, no extra spaces, no upper-case hex digits. A pointer
  therefore has exactly one text form, and two pointers to the same object are the same bytes.
- A pointer is at most 124 bytes long, which tells pointers from documents without reading large files.

A reader that has the object checks that the object's length is the length the size implies.

## Key file

A directory key store keeps each document key wrapped with a 32-byte store key that the application keeps elsewhere:

```
key file = "legix-key/1\n" || nonce || wrapped                12 + 24 + 48 = 84 bytes
nonce    = 24 random bytes, new for every key file
wrapped  = XChaCha20-Poly1305-Encrypt(store_key, nonce, document_key,
                                      associated data = "legix-crypt/1 key " || oid)
```

`oid` in the associated data is the object's 32 bytes, not its text. A key file therefore opens only with its store key
and only as the key of its object.

## Directory layout

An object store and a directory key store name their files by the object's id: the first two hex digits are a directory,
the other 62 the file name.

```
<object store>/<2 hex>/<62 hex>                 the object
<key store>/keys/<2 hex>/<62 hex>               the key file
<key store>/erased/<2 hex>/<62 hex>             an empty file: the key was erased
```

Files are written to a temporary name in the same file system and renamed into place once complete. Names that start
with `.` are temporary files.

## Erasure

Erasing a document destroys its key. A key store:

- records the erasure, and from then on answers that the key was erased;
- refuses to keep a key for an erased object, so that a copy of the key that arrives later — from a backup or from
  another device — cannot bring the document back;
- for a key file, writes the erasure record first, then overwrites the key file with zeros and removes it.

The repository is not changed: the pointer, the commits that hold it and their signatures stay valid. What stays known
after erasure is what the history holds — that a document of the pointer's size was committed, at its path, at its time.

## Test vectors

Document key `00 01 02 … 1f`, salt `a0 a1 a2 … af`.

| Document | Object length | Object id |
|---|---|---|
| `Heads of terms` (14 bytes) | 92 | `blake3:c0d50151e78d1ba23494e2c884809eedd6d770f49ffb4cb797cecb633e0b20b8` |
| empty | 78 | `blake3:c0437b88659de4395d4fbca8675386ec875489f0312813467c9c923a91f45840` |
| 65536 zero bytes | 65614 | `blake3:f488d0f7fcd6ed32e211192599e380dc967537e44c9b640aee43d5f8d6929fc3` |
| 131172 bytes, byte `i` = `i mod 251` | 131282 | `blake3:38de8dc5130e3e5086495b97931b99ba21fc356b02d56bd930e9086c23d3e23c` |

The object for `Heads of terms`:

```
6c656769782d63727970742f310aa0a1a2a3a4a5a6a7a8a9aaabacadaeaf7c70a62d5c3ea14354e8cd619ea906bcc20db98891e16c
0307f55211da8f2de9377d299cea8535a4bc63d472194a08a5739afd60127b3b1e41331df8050d
```

Its key file, for store key `40 41 … 5f` and nonce `10 11 … 27`:

```
6c656769782d6b65792f310a101112131415161718191a1b1c1d1e1f2021222324252627524aeb4005f948255478563928585cf9
143dd2e3b429d5db09a7b4562c252f00e341ca84d4c848f2fe6c9e4b7f61f045
```
