# Signalforge dotenv Extension Specification

## Document Version
- **Version**: 1.0.0-draft
- **Date**: 2025-12-24
- **Status**: DRAFT - Pending Implementation

## Executive Summary

This specification defines a PHP 8.5 C extension implementing dotenvx-compatible environment variable management with integrated encryption support. The extension provides:

1. Secure `.env` file parsing with full dotenvx format compatibility
2. ECIES-based encryption/decryption using secp256k1
3. Zero external PHP dependencies
4. Runtime environments: CLI, PHP-FPM, Swoole

---

## Part 1: Research Findings

### 1.1 dotenvx Overview

**dotenvx** is a secure evolution of the classic dotenv library, created by the original dotenv author (Scott Motte). It extends the standard `.env` file format with:

- Public-key encryption for secrets
- Multi-environment configuration support
- Variable expansion and command substitution
- Separation of encryption (public) and decryption (private) capabilities

**Sources:**
- [dotenvx Official Site](https://dotenvx.com/)
- [dotenvx GitHub Repository](https://github.com/dotenvx/dotenvx)
- [dotenvx Encryption Documentation](https://dotenvx.com/docs/quickstart/encryption)

### 1.2 Encryption Model

#### 1.2.1 Algorithm Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Asymmetric | secp256k1 (ECDSA curve) | Key exchange |
| Key Agreement | ECDH | Shared secret derivation |
| Key Derivation | HKDF | Symmetric key derivation |
| Symmetric | AES-256-GCM | Payload encryption |
| Scheme | ECIES | Integrated encryption scheme |

#### 1.2.2 Key Format

**Private Key (`DOTENV_PRIVATE_KEY`)**:
- 256-bit secp256k1 private key
- Encoded as 64-character lowercase hexadecimal string
- Example: `81dac4d2c42e67a2c6542d3b943a4674a05c4be5e7e5a40a689be7a3bd49a07e`

**Public Key (`DOTENV_PUBLIC_KEY`)**:
- Compressed secp256k1 public key (33 bytes)
- Encoded as 66-character hexadecimal string
- Prefix: `02` (y-coord even) or `03` (y-coord odd)
- Example: `03f8b376234c4f2f0445f392a12e80f3a84b4b0d1e0c3df85c494e45812653c22a`

#### 1.2.3 Encrypted Value Format

```
encrypted:<base64-encoded-ciphertext>
```

The ciphertext structure (before base64 encoding):
```
+------------------+-------+------------+-----+
| Ephemeral PubKey | Nonce | Ciphertext | Tag |
| (33 bytes)       | (12b) | (variable) | (16)|
+------------------+-------+------------+-----+
```

- **Ephemeral Public Key**: 33 bytes (compressed secp256k1)
- **Nonce/IV**: 12 bytes (AES-256-GCM standard)
- **Ciphertext**: Variable length (encrypted plaintext)
- **Authentication Tag**: 16 bytes (GCM tag)

**ECIES Encryption Process:**
1. Generate ephemeral secp256k1 keypair
2. Perform ECDH: `shared_secret = ECDH(ephemeral_private, recipient_public)`
3. Derive symmetric key via HKDF: `aes_key = HKDF(shared_secret, info="dotenvx")`
4. Encrypt with AES-256-GCM: `ciphertext, tag = AES-GCM(aes_key, nonce, plaintext)`
5. Concatenate: `ephemeral_public || nonce || ciphertext || tag`
6. Base64 encode and prefix with `encrypted:`

### 1.3 File Formats

#### 1.3.1 `.env` File Format

```ini
# Comment line
DOTENV_PUBLIC_KEY="03f8b376234c4f2f0445f392a12e80f3a84b4b0d1e0c3df85c494e45812653c22a"

# Plaintext value
DEBUG=true

# Encrypted value
DATABASE_PASSWORD="encrypted:BG8M6U+GKJGwpGA..."

# Variable expansion (double-quoted or unquoted)
DATABASE_URL="postgres://user:${DATABASE_PASSWORD}@localhost/db"

# Literal value (single-quoted, no expansion)
REGEX_PATTERN='pa$$word.*'

# Command substitution
HOSTNAME="$(hostname)"
```

**Parsing Rules:**
- Lines starting with `#` are comments
- Blank lines are ignored
- Key format: `[a-zA-Z_][a-zA-Z0-9_]*`
- Values may be unquoted, single-quoted, or double-quoted
- Escape sequences (`\n`, `\r`, `\t`, `\\`) work in double-quoted values only

#### 1.3.2 `.env.keys` File Format

```ini
#/------------------!DOTENV_PRIVATE_KEYS!-------------------/
#/ private decryption keys. DO NOT commit to source control /
#/     [how it works](https://dotenvx.com/encryption)       /
#/----------------------------------------------------------/

# .env
DOTENV_PRIVATE_KEY="81dac4d2c42e67a2c6542d3b943a4674a05c4be5e7e5a40a689be7a3bd49a07e"

# .env.production
DOTENV_PRIVATE_KEY_PRODUCTION="abc123..."
```

**Key Naming Convention:**
- `DOTENV_PRIVATE_KEY` → decrypts `.env`
- `DOTENV_PRIVATE_KEY_{ENVIRONMENT}` → decrypts `.env.{environment}`

### 1.4 Variable Expansion

#### 1.4.1 Basic Expansion
```ini
USERNAME="admin"
GREETING="Hello, ${USERNAME}"      # → "Hello, admin"
GREETING2="Hello, $USERNAME"       # → "Hello, admin" (braces optional)
```

#### 1.4.2 Default Values
```ini
# Use default if VAR is unset or empty
DATABASE="${DB_HOST:-localhost}"

# Use default only if VAR is unset (empty string allowed)
DATABASE="${DB_HOST-localhost}"
```

#### 1.4.3 Alternate Values
```ini
# Use alternate if VAR is set and non-empty
DEBUG_MODE="${DEBUG:+enabled}"
```

#### 1.4.4 Command Substitution
```ini
CURRENT_USER="$(whoami)"
TIMESTAMP="$(date +%s)"
```

### 1.5 Security Model

#### 1.5.1 Threat Model

**Protected Against:**
- Leaked `.env` files (without private key)
- Source control exposure of encrypted configs
- Separation of encryption and decryption capabilities
- Per-secret encryption with unique ephemeral keys

**Not Protected Against:**
- Memory inspection of running process
- Compromised private key
- Side-channel attacks on the host system

#### 1.5.2 Blast Radius Reduction

The dotenvx model requires an attacker to obtain BOTH:
1. The encrypted `.env` file (from source control)
2. The `DOTENV_PRIVATE_KEY` (from secrets manager)

This separation means a breach of either system alone does not compromise secrets.

### 1.6 Differences from Classic PHP dotenv

| Feature | vlucas/phpdotenv | dotenvx | This Spec |
|---------|------------------|---------|-----------|
| Encryption | No | Yes (ECIES) | Yes (ECIES) |
| Variable Expansion | Yes | Yes | Yes |
| Command Substitution | No | Yes | Optional |
| Multi-environment | Manual | Built-in | Built-in |
| Key Rotation | N/A | Yes | Yes |
| Implementation | PHP | Node.js | C Extension |
| Dependencies | Composer | npm | None |

---

## Part 2: Feature Specification

### 2.1 Parsing Features

#### 2.1.1 Core Parsing (MUST)
- [ ] Parse `KEY=value` format
- [ ] Support unquoted values
- [ ] Support single-quoted values (literal, no expansion)
- [ ] Support double-quoted values (with expansion)
- [ ] Skip blank lines
- [ ] Skip comment lines (starting with `#`)
- [ ] Handle inline comments (after space for unquoted, after quote for quoted)
- [ ] Parse escape sequences in double-quoted values: `\n`, `\r`, `\t`, `\\`, `\"`
- [ ] Handle UTF-8 values correctly

#### 2.1.2 Variable Expansion (MUST)
- [ ] Expand `${VAR}` syntax
- [ ] Expand `$VAR` syntax (without braces)
- [ ] Support default value: `${VAR:-default}`
- [ ] Support default if unset only: `${VAR-default}`
- [ ] Support alternate value: `${VAR:+alternate}`
- [ ] Disable expansion in single-quoted strings
- [ ] Recursive expansion (expand variables in expanded values)
- [ ] Inherit from existing environment variables

#### 2.1.3 Multiline Values (SHOULD)
- [ ] Support multiline in double-quoted values with literal newlines
- [ ] Support `\n` escape sequence for newlines

#### 2.1.4 Command Substitution (MAY - SECURITY CONSIDERATION)
- [ ] Support `$(command)` syntax
- [ ] Execute via shell subprocess
- [ ] **MUST be opt-in and disabled by default** (security risk)

### 2.2 Encryption Features

#### 2.2.1 Key Management (MUST)
- [ ] Generate secp256k1 keypair
- [ ] Parse 64-char hex private keys
- [ ] Parse 66-char hex compressed public keys
- [ ] Load private key from `DOTENV_PRIVATE_KEY` env var
- [ ] Load private key from `.env.keys` file
- [ ] Support environment-specific keys: `DOTENV_PRIVATE_KEY_{ENV}`
- [ ] Support multiple comma-separated private keys

#### 2.2.2 Encryption (MUST)
- [ ] Implement ECIES with secp256k1
- [ ] Generate ephemeral keypair per encryption
- [ ] Derive shared secret via ECDH
- [ ] Derive AES key via HKDF-SHA256
- [ ] Encrypt with AES-256-GCM
- [ ] Output format: `encrypted:<base64>`

#### 2.2.3 Decryption (MUST)
- [ ] Detect `encrypted:` prefix
- [ ] Decode base64 payload
- [ ] Extract ephemeral public key (33 bytes)
- [ ] Extract nonce (12 bytes)
- [ ] Extract ciphertext and tag
- [ ] Derive shared secret via ECDH
- [ ] Derive AES key via HKDF-SHA256
- [ ] Decrypt and verify with AES-256-GCM
- [ ] Handle decryption failures gracefully

#### 2.2.4 Key Rotation (SHOULD)
- [ ] Re-encrypt all values with new keypair
- [ ] Preserve unencrypted values
- [ ] Update public key in `.env` file
- [ ] Update private key in `.env.keys` file

### 2.3 Runtime Behavior

#### 2.3.1 Loading (MUST)
- [ ] Load from default `.env` file
- [ ] Load from specified file path(s)
- [ ] Load multiple files in order (later files can override)
- [ ] Auto-detect and decrypt encrypted values
- [ ] Inject into `$_ENV` superglobal
- [ ] Inject into `$_SERVER` superglobal
- [ ] Inject via `putenv()` (optional, configurable)

#### 2.3.2 Environment Precedence (MUST)
- [ ] By default: existing env vars take precedence (no overwrite)
- [ ] Overload mode: `.env` values override existing env vars
- [ ] Strict mode: error on missing/invalid files

#### 2.3.3 Multi-Environment Support (MUST)
- [ ] Support `.env.{environment}` naming convention
- [ ] Auto-detect environment from `APP_ENV` or `DOTENV_ENV`
- [ ] Support `.env.local` overrides

#### 2.3.4 Framework Conventions (SHOULD)
- [ ] Next.js convention: `.env.local`, `.env.development.local`, etc.
- [ ] dotenv-flow convention

### 2.4 Developer UX / Ergonomics

#### 2.4.1 Error Handling (MUST)
- [ ] Clear error messages for parse failures
- [ ] Clear error messages for decryption failures
- [ ] Indicate which file and line caused the error
- [ ] Non-fatal warnings for missing optional files

#### 2.4.2 Debugging (SHOULD)
- [ ] Debug mode with verbose output
- [ ] Log which files were loaded
- [ ] Log which keys were decrypted
- [ ] Log variable expansion steps

### 2.5 Security Constraints

#### 2.5.1 Memory Safety (MUST)
- [ ] Zero plaintext secrets after use where possible
- [ ] No debug output of decrypted values in production
- [ ] Constant-time comparison for authentication tags

#### 2.5.2 Input Validation (MUST)
- [ ] Validate key format before use
- [ ] Validate encrypted payload structure
- [ ] Reject malformed base64
- [ ] Reject invalid ciphertext lengths

#### 2.5.3 Command Substitution Security (MUST if implemented)
- [ ] Disabled by default
- [ ] Require explicit opt-in
- [ ] Document security implications
- [ ] Consider sandboxing or command whitelist

### 2.6 CLI vs Runtime Differences

| Capability | CLI Tool | Runtime API |
|------------|----------|-------------|
| Parse `.env` | Yes | Yes |
| Decrypt values | Yes | Yes |
| Encrypt values | Yes | Yes |
| Generate keypair | Yes | Yes |
| Key rotation | Yes | Optional |
| Write `.env` file | Yes | No |
| Write `.env.keys` | Yes | No |
| Command substitution | Yes (opt-in) | Optional (opt-in) |

---

## Part 3: Signalforge Extension Specification

### 3.1 Extension Metadata

```
Extension Name: signalforge_dotenv
Version: 1.0.0
PHP Version: >= 8.5.0
Thread Safety: Yes (ZTS compatible)
Dependencies: OpenSSL (bundled with PHP)
```

### 3.2 INI Directives

```ini
; Enable/disable the extension
signalforge_dotenv.enabled = On

; Default .env file path (relative to document root or absolute)
signalforge_dotenv.path = ".env"

; Auto-load .env on RINIT (request init)
signalforge_dotenv.auto_load = Off

; Environment variable for environment detection
signalforge_dotenv.env_var = "APP_ENV"

; Overload mode (override existing env vars)
signalforge_dotenv.overload = Off

; Enable putenv() injection (in addition to $_ENV/$_SERVER)
signalforge_dotenv.putenv = Off

; Enable command substitution (SECURITY RISK)
signalforge_dotenv.command_substitution = Off

; Path to .env.keys file
signalforge_dotenv.keys_path = ".env.keys"
```

### 3.3 PHP API Surface

#### 3.3.1 Namespace and Classes

```php
namespace Signalforge\Dotenv;

/**
 * Main entry point for dotenv operations
 */
final class Dotenv
{
    /**
     * Load and parse .env file(s), injecting into environment
     *
     * @param string|array $paths File path(s) to load
     * @param array $options {
     *     @type bool $overload Override existing env vars (default: false)
     *     @type bool $strict Error on missing files (default: false)
     *     @type string|null $privateKey Private key for decryption
     *     @type string|null $keysPath Path to .env.keys file
     * }
     * @return array<string, string> Parsed key-value pairs
     * @throws ParseException On parse error
     * @throws DecryptionException On decryption failure
     */
    public static function load(
        string|array $paths = '.env',
        array $options = []
    ): array;

    /**
     * Parse .env content without injecting into environment
     *
     * @param string $content Raw .env file content
     * @param array $options Same as load()
     * @return array<string, string> Parsed key-value pairs
     */
    public static function parse(
        string $content,
        array $options = []
    ): array;

    /**
     * Get a single environment variable (with decryption if needed)
     *
     * @param string $key Variable name
     * @param string|null $default Default value if not set
     * @return string|null
     */
    public static function get(string $key, ?string $default = null): ?string;

    /**
     * Check if a variable exists
     */
    public static function has(string $key): bool;

    /**
     * Get all loaded variables
     *
     * @return array<string, string>
     */
    public static function all(): array;
}

/**
 * Encryption and key management
 */
final class Encryption
{
    /**
     * Generate a new keypair
     *
     * @return array{publicKey: string, privateKey: string}
     */
    public static function generateKeypair(): array;

    /**
     * Encrypt a value
     *
     * @param string $plaintext Value to encrypt
     * @param string $publicKey 66-char hex public key
     * @return string Encrypted value with "encrypted:" prefix
     * @throws EncryptionException On failure
     */
    public static function encrypt(string $plaintext, string $publicKey): string;

    /**
     * Decrypt a value
     *
     * @param string $ciphertext Value with "encrypted:" prefix
     * @param string $privateKey 64-char hex private key
     * @return string Decrypted plaintext
     * @throws DecryptionException On failure
     */
    public static function decrypt(string $ciphertext, string $privateKey): string;

    /**
     * Check if a value is encrypted
     */
    public static function isEncrypted(string $value): bool;

    /**
     * Derive public key from private key
     *
     * @param string $privateKey 64-char hex private key
     * @return string 66-char hex public key
     */
    public static function derivePublicKey(string $privateKey): string;
}

/**
 * Exception types
 */
class DotenvException extends \Exception {}
class ParseException extends DotenvException {}
class EncryptionException extends DotenvException {}
class DecryptionException extends DotenvException {}
class FileNotFoundException extends DotenvException {}
```

#### 3.3.2 Procedural API (Optional)

```php
/**
 * Load .env file(s)
 * @see \Signalforge\Dotenv\Dotenv::load()
 */
function dotenv_load(string|array $paths = '.env', array $options = []): array;

/**
 * Parse .env content
 * @see \Signalforge\Dotenv\Dotenv::parse()
 */
function dotenv_parse(string $content, array $options = []): array;

/**
 * Get environment variable
 * @see \Signalforge\Dotenv\Dotenv::get()
 */
function dotenv_get(string $key, ?string $default = null): ?string;

/**
 * Generate encryption keypair
 * @see \Signalforge\Dotenv\Encryption::generateKeypair()
 */
function dotenv_keypair(): array;

/**
 * Encrypt a value
 * @see \Signalforge\Dotenv\Encryption::encrypt()
 */
function dotenv_encrypt(string $plaintext, string $publicKey): string;

/**
 * Decrypt a value
 * @see \Signalforge\Dotenv\Encryption::decrypt()
 */
function dotenv_decrypt(string $ciphertext, string $privateKey): string;
```

### 3.4 Implementation Approach

#### 3.4.1 Cryptography

**Use OpenSSL (bundled with PHP):**
- secp256k1 curve support via `EC` key type
- ECDH via `EVP_PKEY_derive()`
- AES-256-GCM via `EVP_aes_256_gcm()`
- HKDF via `EVP_KDF` (OpenSSL 3.0+) or manual HMAC-based HKDF

**Alternative: libsecp256k1**
If OpenSSL's secp256k1 support is insufficient, bundle or link against `libsecp256k1` from Bitcoin Core.

**HKDF Parameters:**
```
Algorithm: HKDF-SHA256
IKM: ECDH shared secret (32 bytes)
Salt: Empty (as per dotenvx)
Info: "dotenvx" (or empty, needs verification)
Output: 32 bytes (AES-256 key)
```

#### 3.4.2 Parser Implementation

The parser should be implemented as a state machine handling:

1. **Line tokenization** - split by newlines, handle `\r\n` and `\n`
2. **Comment/blank detection** - skip lines starting with `#` or whitespace-only
3. **Key extraction** - validate `[a-zA-Z_][a-zA-Z0-9_]*` pattern
4. **Value extraction** - handle quoting modes
5. **Expansion pass** - resolve `${}` references after initial parse
6. **Decryption pass** - decrypt `encrypted:` values

#### 3.4.3 Memory Management

- Use PHP's memory allocator (`emalloc`, `efree`, `ZSTR_*`)
- Zero sensitive data after use (`explicit_bzero` or `OPENSSL_cleanse`)
- Avoid storing decrypted values longer than necessary

#### 3.4.4 Thread Safety (ZTS)

- Use `TSRMLS_*` macros for thread-local storage
- No global mutable state
- Lock around OpenSSL operations if necessary (OpenSSL 1.1+ is thread-safe)

### 3.5 File Format Recommendations

#### 3.5.1 Encrypted Value Format

Maintain dotenvx compatibility:
```
encrypted:<base64(ephemeral_pubkey || nonce || ciphertext || tag)>
```

#### 3.5.2 Key File Format

Maintain dotenvx `.env.keys` compatibility for interoperability.

### 3.6 Runtime Environment Support

#### 3.6.1 CLI
- Load on first `Dotenv::load()` call
- Persist for process lifetime
- Full feature support including command substitution (if enabled)

#### 3.6.2 PHP-FPM (Non-ZTS)
- Optional auto-load via `RINIT` hook
- Per-request isolation (values cleared on `RSHUTDOWN`)
- Shared file parsing cache (opcode-style) for performance

#### 3.6.3 Swoole / Long-Running Processes
- Explicit load required (no auto-load)
- Provide `Dotenv::reload()` method for hot-reload
- Consider memory implications of holding secrets long-term

### 3.7 Compatibility Matrix

| Feature | dotenvx CLI | This Extension |
|---------|-------------|----------------|
| Parse `.env` | ✓ | ✓ |
| Encrypted values | ✓ | ✓ |
| Variable expansion | ✓ | ✓ |
| Command substitution | ✓ | ✓ (opt-in) |
| Multi-file loading | ✓ | ✓ |
| `.env.keys` format | ✓ | ✓ |
| `encrypted:` prefix | ✓ | ✓ |
| Key format (hex) | ✓ | ✓ |
| Next.js convention | ✓ | ✓ |
| Write `.env` files | ✓ | ✗ |
| CLI tool | ✓ | Separate binary |

---

## Part 4: Non-Goals

The following are explicitly **NOT** goals of this extension:

### 4.1 File Writing
- The extension will NOT write or modify `.env` files
- File generation/encryption is a CLI tool concern
- A separate CLI binary may be provided

### 4.2 Vault Integration
- No integration with HashiCorp Vault, AWS Secrets Manager, etc.
- The extension handles local file encryption only
- External secret managers should be handled by userland code

### 4.3 Web UI / Dashboard
- No web interface for key management
- No dotenvx.com cloud integration

### 4.4 Legacy Format Support
- No support for deprecated `DOTENV_KEY` URI format
- No support for `.env.vault` files
- Focus on current dotenvx format only

### 4.5 PHP < 8.5
- No backports to older PHP versions
- Target PHP 8.5 for modern extension APIs

### 4.6 Composer Autoloading
- The extension loads independently of Composer
- No `vendor/autoload.php` integration needed

### 4.7 Framework-Specific Bindings
- No Laravel/Symfony/etc. service providers
- Frameworks can wrap the extension API themselves

### 4.8 Environment Variable Sanitization
- No type coercion (`"true"` → `bool`)
- No validation rules
- Returns raw string values only

---

## Part 5: Open Questions

The following items require clarification or decision:

### 5.1 HKDF Parameters
- **Question**: What exact HKDF info string does dotenvx use?
- **Status**: Needs verification from source code
- **Fallback**: Use empty info string for now, document for compatibility testing

### 5.2 Compressed vs Uncompressed Keys
- **Question**: Does dotenvx use compressed public keys in the encrypted payload?
- **Evidence**: Documentation shows 66-char public keys (compressed)
- **Status**: Likely compressed, needs verification

### 5.3 Nonce Generation
- **Question**: How are nonces generated? Random or deterministic?
- **Assumption**: Random 12-byte nonce per encryption
- **Status**: Standard practice, likely correct

### 5.4 Command Substitution Scope
- **Question**: Should command substitution be supported at all in a C extension?
- **Security Risk**: Executing arbitrary shell commands from config files
- **Recommendation**: Implement but disable by default, require explicit opt-in

### 5.5 Auto-Load Timing
- **Question**: When should auto-load occur in PHP-FPM?
- **Options**: RINIT (after `php.ini`), first access, lazy
- **Recommendation**: RINIT if enabled, otherwise explicit call

---

## Part 6: References

### Official Documentation
- [dotenvx Official Site](https://dotenvx.com/)
- [dotenvx GitHub Repository](https://github.com/dotenvx/dotenvx)
- [dotenvx Encryption Quickstart](https://dotenvx.com/docs/quickstart/encryption)
- [.env File Format](https://dotenvx.com/docs/env-file)
- [.env.keys File Format](https://dotenvx.com/docs/env-keys-file)

### Implementation References
- [Rust dotenvx Implementation](https://github.com/fabianopinto/dotenvx)
- [ECIES Python Library](https://github.com/ecies/py)
- [libsecp256k1](https://github.com/bitcoin-core/secp256k1)

### Cryptographic Standards
- [ECIES (SEC 1, Section 5.1)](https://www.secg.org/sec1-v2.pdf)
- [AES-GCM (NIST SP 800-38D)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [HKDF (RFC 5869)](https://tools.ietf.org/html/rfc5869)
- [secp256k1 Parameters](https://www.secg.org/sec2-v2.pdf)

---

## Appendix A: Example Files

### A.1 Example `.env` File
```ini
#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY="03f8b376234c4f2f0445f392a12e80f3a84b4b0d1e0c3df85c494e45812653c22a"

# Application
APP_NAME="MyApp"
APP_ENV=production
DEBUG=false

# Database (encrypted)
DB_HOST="encrypted:BGJ8J4sEy1RkHy..."
DB_USER="encrypted:BKm8pZ3XyQ7YiN..."
DB_PASS="encrypted:BJk2mN3pQr5StU..."

# Computed
DATABASE_URL="postgres://${DB_USER}:${DB_PASS}@${DB_HOST}/myapp"
```

### A.2 Example `.env.keys` File
```ini
#/------------------!DOTENV_PRIVATE_KEYS!-------------------/
#/ private decryption keys. DO NOT commit to source control /
#/     [how it works](https://dotenvx.com/encryption)       /
#/----------------------------------------------------------/

# .env
DOTENV_PRIVATE_KEY="81dac4d2c42e67a2c6542d3b943a4674a05c4be5e7e5a40a689be7a3bd49a07e"

# .env.production
DOTENV_PRIVATE_KEY_PRODUCTION="9f2d8c7b6a5e4f3d2c1b0a9e8d7c6b5a4f3e2d1c0b9a8d7e6f5c4b3a2d1e0f9c"
```

### A.3 Example PHP Usage
```php
<?php

use Signalforge\Dotenv\Dotenv;
use Signalforge\Dotenv\Encryption;

// Basic loading
$env = Dotenv::load();

// Multi-file with options
$env = Dotenv::load(
    ['.env', '.env.local', '.env.production'],
    [
        'overload' => true,
        'strict' => true,
    ]
);

// Get specific value
$dbPass = Dotenv::get('DB_PASS');

// Generate new keypair
$keys = Encryption::generateKeypair();
echo "Public: {$keys['publicKey']}\n";
echo "Private: {$keys['privateKey']}\n";

// Encrypt a new secret
$encrypted = Encryption::encrypt('my-secret-value', $keys['publicKey']);
echo "Encrypted: {$encrypted}\n";

// Decrypt
$decrypted = Encryption::decrypt($encrypted, $keys['privateKey']);
echo "Decrypted: {$decrypted}\n";
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0-draft | 2025-12-24 | Signalforge | Initial specification |
