# ratarmount-formats-sqlar

SQLAR ([SQLite Archiver](https://www.sqlite.org/sqlar.html)) mount source for the Rust ratarmount rewrite — Python `SQLARMountSource` parity.

## Features

| Feature | Default | Purpose |
|---------|---------|---------|
| *(none)* | yes | Unencrypted SQLAR via stock bundled SQLite |
| `sqlcipher` | no | Open SQLCipher-encrypted `.sqlar` archives |

## Encrypted SQLAR

Encrypted archives **omit** the `SQLite format 3\0` magic; the first 16 bytes are the AES salt. Detection still works on `*.sqlar` files without the magic.

| Situation | Error |
|-----------|--------|
| Encrypted, no password | `SqlarError::EncryptedRequiresPassword` |
| Encrypted, password(s) given, **no** `sqlcipher` feature | `SqlarError::EncryptedNotSupported` |
| Encrypted, wrong password(s), with `sqlcipher` | `SqlarError::WrongPassword` |

With `sqlcipher` enabled, passwords from `OpenOptions::passwords` (CLI `--password`) are tried in order:

1. `PRAGMA key = '<passphrase>'` (SQLCipher-internal KDF)
2. PBKDF2-HMAC-SHA512 raw key (`PRAGMA key = "x'…'"`) — matches Python `sqlcipher3` / cryptography

Probe at runtime with `sqlcipher_enabled()`.

## Build / test with SQLCipher

```bash
# Library
cargo build -p ratarmount-formats-sqlar --features sqlcipher
cargo test  -p ratarmount-formats-sqlar --features sqlcipher --lib
cargo clippy -p ratarmount-formats-sqlar --all-targets --features sqlcipher -- -D warnings

# Default (no decryption — still detects encrypted files and returns clear errors)
cargo test -p ratarmount-formats-sqlar --lib
```

Enabling `sqlcipher` pulls in `rusqlite`’s `bundled-sqlcipher-vendored-openssl` (vendored OpenSSL + SQLCipher amalgamation). First compile can take several minutes.

### Dependents

Forward the feature from a binary or library crate:

```toml
[dependencies]
ratarmount-formats-sqlar = { path = "../ratarmount-formats-sqlar" }

[features]
sqlcipher = ["ratarmount-formats-sqlar/sqlcipher"]
```

```bash
cargo build -p ratarmount --features sqlcipher
```

## Fixtures / tests

Unit tests under `src/lib.rs` load Python ratarmount fixtures from:

```text
$RATARMOUNT_PY_ROOT/tests/
  nested-tar.sqlar
  nested-tar-compressed.sqlar
  nested-tar-denormal.sqlar
  nested-tar-trailing-slash.sqlar
  encrypted-nested-tar.sqlar   # password: foo
```

If a fixture is missing, the test **skips cleanly** (prints a message; does not fail). Unencrypted coverage does not require `sqlcipher`. Encrypted open/decrypt coverage runs when the fixture is present; decrypt succeeds only with `--features sqlcipher`.

```bash
export RATARMOUNT_PY_ROOT=/path/to/python/ratarmount
cargo test -p ratarmount-formats-sqlar --lib
cargo test -p ratarmount-formats-sqlar --lib --features sqlcipher
```
