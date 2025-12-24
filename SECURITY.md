# Security Notes

## Cryptographic Design

### Algorithm Selection

The extension uses **libsodium** for all cryptographic operations:

| Purpose | Algorithm | Justification |
|---------|-----------|---------------|
| Key Derivation | Argon2id | Memory-hard, winner of Password Hashing Competition |
| Symmetric Encryption | XSalsa20-Poly1305 | Modern AEAD cipher, part of NaCl/libsodium |

### Why Not ECIES/secp256k1 (dotenvx)?

The original dotenvx uses ECIES with secp256k1 (Bitcoin's curve). We chose a different approach:

1. **Library Availability**: libsodium is bundled with PHP; secp256k1 requires external linking
2. **Complexity**: Public-key crypto adds key management complexity
3. **Use Case**: For file encryption, passphrase-based is often more practical
4. **Security Margin**: Argon2id provides excellent brute-force resistance

### Key Derivation Parameters

```c
// Argon2id parameters (MODERATE)
crypto_pwhash_OPSLIMIT_MODERATE  // 3 iterations
crypto_pwhash_MEMLIMIT_MODERATE  // 256 MB memory
```

These settings provide:
- ~0.7 seconds per derivation on modern hardware
- Resistance against GPU/ASIC attacks
- Balance between security and usability

### Encryption Format

```
SFDOTENV | Ver | Reserved | Salt (16) | Nonce (24) | Ciphertext + MAC
```

- **Magic bytes**: Identify encrypted files, prevent format confusion
- **Version**: Enable future format upgrades
- **Salt**: Unique per-file, prevents rainbow tables
- **Nonce**: Random per-encryption, prevents nonce reuse
- **MAC**: 16-byte Poly1305 tag for authentication

## Memory Security

### Sensitive Data Handling

```c
// After use, key material is zeroed
sodium_memzero(key, sizeof(key));

// Decrypted content is zeroed before free
sf_crypto_secure_zero(plaintext, plaintext_len);
```

### What Gets Zeroed

- Encryption keys
- Decryption keys
- Raw file content after parsing
- Intermediate buffers during crypto operations

### What Cannot Be Zeroed

- PHP string zvals (managed by Zend engine)
- Return values (visible to PHP code)

## Request Isolation

### PHP-FPM Behavior

Each request:
1. Initializes fresh module globals (`RINIT`)
2. Parses files independently
3. Cleans up on shutdown (`RSHUTDOWN`)

No data persists between requests.

### Environment Variable Cleanup

```c
// Tracked for cleanup
static sf_putenv_tracker_t putenv_tracker;

// Freed on request shutdown
sf_env_cleanup_putenv();
```

**Note**: Due to POSIX limitations, environment strings passed to `putenv()` cannot be safely unset. They are freed when the PHP process exits.

## Input Validation

### Key Name Validation

```c
// Only valid env var names accepted
bool sf_env_validate_key(const char *key, size_t key_len)
{
    // Must match: [a-zA-Z_][a-zA-Z0-9_]*
}
```

### File Path Safety

- No path traversal prevention (OS handles this)
- Caller is responsible for validating paths
- Extension reads files in binary mode

## Error Handling

### Fail-Closed Behavior

On any decryption error:
1. All sensitive buffers are zeroed
2. Exception is thrown
3. No partial data is returned

```c
if (crypto_err != SF_CRYPTO_OK) {
    sf_crypto_secure_zero(plaintext, plaintext_len);
    efree(plaintext);
    zend_throw_exception(...);
    RETURN_THROWS();
}
```

### Error Messages

Error messages are designed to:
- Provide enough info for debugging
- Not leak sensitive data
- Not reveal internal state

**Example**: "Decryption failed: wrong key or tampered data"
- Does NOT say which one
- Does NOT reveal expected/actual values

## Timing Safety

### Constant-Time Comparisons

```c
// Uses libsodium's constant-time compare
int sf_crypto_compare(const void *a, const void *b, size_t len)
{
    return sodium_memcmp(a, b, len);
}
```

Used for:
- Magic byte verification
- MAC verification (handled by secretbox_open)

## Known Limitations

### 1. In-Memory Secrets

Once decrypted, secrets exist in PHP memory:
- Accessible via `$_ENV`, return values
- May be swapped to disk
- Visible in process memory

**Mitigation**: Use short-lived processes, enable swap encryption

### 2. Environment Leakage

Environment variables may leak via:
- `/proc/[pid]/environ` (Linux)
- `ps eww` (some systems)
- Child processes

**Mitigation**: Use `export => false` when possible

### 3. Logging

PHP may log:
- Error messages containing paths
- Exception stack traces

**Mitigation**: Configure error logging carefully in production

### 4. Core Dumps

Process crashes may dump memory including secrets.

**Mitigation**: Disable core dumps in production (`ulimit -c 0`)

## Recommendations

### Key Management

```bash
# Generate strong passphrase
openssl rand -base64 32

# Store in secret manager, not in repo
vault kv put secret/app DOTENV_KEY=...
```

### File Permissions

```bash
# .env files
chmod 600 .env
chown www-data:www-data .env

# .env.encrypted (can be less restrictive)
chmod 644 .env.encrypted
```

### Deployment

```bash
# Never commit unencrypted .env
echo ".env" >> .gitignore

# Encrypted files are safe to commit
git add .env.encrypted
```

### Monitoring

Log failed decryption attempts:
```php
try {
    $env = \Signalforge\dotenv('.env.enc');
} catch (\Signalforge\DotenvException $e) {
    // Log for security monitoring
    error_log("SECURITY: dotenv decryption failed: " . $e->getCode());
    throw $e;
}
```

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do NOT** open a public issue
2. Email: security@signalforge.example.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and patch within 7 days for critical issues.
