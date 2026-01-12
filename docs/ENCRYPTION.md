# Encrypted Environment Files

The signalforge_dotenv extension provides secure storage for sensitive configuration values in encrypted `.env` files that can be safely committed to version control.

## Overview

Unlike plaintext `.env` files that must be excluded from repositories, encrypted files can be shared among team members and deployed alongside code. The encryption uses industry-standard cryptography via libsodium.

## How Encryption Works

### Cryptographic Design

```
                    User Passphrase
                          |
                          v
              +---------------------------+
              |     Argon2id KDF          |
              | (memory-hard, 256MB RAM)  |
              +---------------------------+
                          |
                          v
                    256-bit Key
                          |
                          v
              +---------------------------+
              |   XSalsa20-Poly1305       |
              |  (Authenticated Cipher)   |
              +---------------------------+
                          |
                          v
                  Encrypted File
```

### Algorithms

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Derivation | Argon2id | Converts passphrase to encryption key (memory-hard, resistant to GPU/ASIC attacks) |
| Encryption | XSalsa20-Poly1305 | Authenticated encryption (confidentiality + integrity) |
| Parameters | MODERATE | ~0.7s derivation, 256MB memory per attempt |

### File Format

Encrypted files use a binary format with a 52-byte header:

```
+------------------+------------------+
|     Field        |     Size         |
+------------------+------------------+
| Magic            | 8 bytes          |  "SFDOTENV"
| Version          | 1 byte           |  0x01
| Reserved         | 3 bytes          |  0x00 0x00 0x00
| Salt             | 16 bytes         |  Random per-file
| Nonce            | 24 bytes         |  Random per-encryption
| Ciphertext + MAC | Variable         |  Encrypted content
+------------------+------------------+
```

- **Magic bytes**: Identify encrypted files for auto-detection
- **Version**: Enable future format upgrades
- **Salt**: Unique per-file, prevents precomputation attacks
- **Nonce**: Random per-encryption, ensures unique ciphertext
- **MAC**: 16-byte Poly1305 authentication tag (appended to ciphertext)

## Generating and Managing Keys

### Choosing a Strong Passphrase

```bash
# Generate a cryptographically random passphrase (recommended)
openssl rand -base64 32
# Example output: K8vM3nP2xR5qT9wL4jF7hB1cN6mS0aE8Y
```

**Requirements:**
- Minimum 16 characters
- Avoid dictionary words or predictable patterns
- Unique per environment (development, staging, production)

### Key Storage Best Practices

**Never store keys in:**
- Source code repositories
- `.env` files themselves
- Shell history
- Plain text files on disk

**Recommended storage:**
- Environment variables (set by deployment system)
- Secret managers (HashiCorp Vault, AWS Secrets Manager, 1Password CLI)
- CI/CD secret stores (GitHub Actions secrets, GitLab CI variables)

## Creating Encrypted Files

Create a file named `encrypt-env.php`:

```php
#!/usr/bin/env php
<?php
/**
 * Encrypt a .env file using the signalforge_dotenv format
 *
 * Usage: php encrypt-env.php <input.env> <output.env.enc> [passphrase]
 */

declare(strict_types=1);

function encrypt_env_file(string $plaintext, string $passphrase): string
{
    // File format constants
    $magic = "SFDOTENV";
    $version = chr(0x01);
    $reserved = str_repeat(chr(0), 3);

    // Generate random salt and nonce
    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);   // 16 bytes
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES); // 24 bytes

    // Derive encryption key using Argon2id (MODERATE parameters)
    $key = sodium_crypto_pwhash(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES,  // 32 bytes
        $passphrase,
        $salt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,  // 3 iterations
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,  // 256 MB
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );

    // Encrypt with XSalsa20-Poly1305
    $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

    // Secure cleanup
    sodium_memzero($key);

    // Construct output: header + ciphertext
    return $magic . $version . $reserved . $salt . $nonce . $ciphertext;
}

// Command-line interface
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

$argc = $_SERVER['argc'];
$argv = $_SERVER['argv'];

if ($argc < 3) {
    echo "Usage: php {$argv[0]} <input.env> <output.env.enc> [passphrase]\n";
    echo "\nIf passphrase is not provided, reads from SIGNALFORGE_DOTENV_KEY env var\n";
    exit(1);
}

$inputFile = $argv[1];
$outputFile = $argv[2];
$passphrase = $argv[3] ?? getenv('SIGNALFORGE_DOTENV_KEY');

if (!$passphrase) {
    fwrite(STDERR, "Error: No passphrase provided.\n");
    fwrite(STDERR, "Set SIGNALFORGE_DOTENV_KEY or pass as third argument.\n");
    exit(1);
}

if (!file_exists($inputFile)) {
    fwrite(STDERR, "Error: Input file not found: $inputFile\n");
    exit(1);
}

$plaintext = file_get_contents($inputFile);
if ($plaintext === false) {
    fwrite(STDERR, "Error: Could not read input file\n");
    exit(1);
}

echo "Encrypting $inputFile...\n";

$encrypted = encrypt_env_file($plaintext, $passphrase);

if (file_put_contents($outputFile, $encrypted) === false) {
    fwrite(STDERR, "Error: Could not write output file\n");
    exit(1);
}

echo "Success! Encrypted file written to: $outputFile\n";
echo "File size: " . strlen($encrypted) . " bytes\n";

// Secure cleanup
sodium_memzero($plaintext);
```

### Usage Examples

```bash
# Encrypt with passphrase from command line
php encrypt-env.php .env .env.encrypted "my-strong-passphrase-here"

# Encrypt with passphrase from environment variable
export SIGNALFORGE_DOTENV_KEY="my-strong-passphrase-here"
php encrypt-env.php .env .env.encrypted

# Encrypt environment-specific files
php encrypt-env.php .env.production .env.production.encrypted
```

## Using Encrypted Files

### Basic Usage

```php
<?php
// The extension automatically detects encrypted files by magic bytes
$env = \Signalforge\dotenv('.env.encrypted', [
    'key' => getenv('SIGNALFORGE_DOTENV_KEY'),
]);

// Values are now available
echo $env['DATABASE_PASSWORD'];
echo getenv('DATABASE_PASSWORD');
```

### Key Sources (Priority Order)

The extension looks for the decryption key in this order:

1. **Direct key option**: `['key' => 'passphrase']`
2. **Custom env var**: `['key_env' => 'MY_CUSTOM_KEY']`
3. **Default env var**: `SIGNALFORGE_DOTENV_KEY`
4. **dotenvx compatibility**: `DOTENV_PRIVATE_KEY`

```php
// Method 1: Direct key (not recommended for production)
$env = \Signalforge\dotenv('.env.enc', ['key' => 'passphrase']);

// Method 2: Custom environment variable
$env = \Signalforge\dotenv('.env.enc', ['key_env' => 'MY_APP_KEY']);

// Method 3: Default environment variable (recommended)
// Set SIGNALFORGE_DOTENV_KEY in your deployment environment
$env = \Signalforge\dotenv('.env.enc'); // Key auto-detected
```

### Auto-Detection

Encrypted files are automatically detected by their `SFDOTENV` magic bytes - no need to specify `'encrypted' => true`.

### Production Deployment

```php
<?php
// bootstrap.php

try {
    $env = \Signalforge\dotenv(__DIR__ . '/.env.encrypted');
} catch (\Signalforge\DotenvException $e) {
    error_log("CRITICAL: Failed to load configuration: " . $e->getCode());
    http_response_code(503);
    exit("Service temporarily unavailable");
}

$dbHost = $env['DB_HOST'] ?? 'localhost';
```

### Kubernetes/Docker Deployment

```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          env:
            - name: SIGNALFORGE_DOTENV_KEY
              valueFrom:
                secretKeyRef:
                  name: app-secrets
                  key: dotenv-key
```

```dockerfile
# Dockerfile
COPY .env.encrypted /app/.env.encrypted
# Key is NOT in the image - injected at runtime
```

## Security Considerations

### What Is Protected

1. **Secrets at rest**: Encrypted files can be safely committed to version control
2. **Tampering detection**: Any modification to the encrypted file will be detected (Poly1305 MAC)
3. **Brute-force resistance**: Argon2id makes password cracking expensive (~256MB RAM per attempt)

### What Is NOT Protected

1. **Compromised keys**: If the passphrase is leaked, all files encrypted with it are compromised
2. **Runtime memory**: Once decrypted, values exist in PHP memory and may be accessible via:
   - `/proc/[pid]/environ` (Linux)
   - Memory dumps / core dumps
   - Debugging tools
3. **Log exposure**: Ensure decrypted values are never logged

### Best Practices Checklist

- [ ] Use unique passphrases per environment (dev/staging/prod)
- [ ] Store passphrases in a secret manager, not source control
- [ ] Rotate keys periodically (re-encrypt with new passphrase)
- [ ] Set `export => false` when you only need parsed values
- [ ] Disable `export_server` in shared hosting environments
- [ ] Restrict file permissions: `chmod 644 .env.encrypted`
- [ ] Never log decrypted values

### Key Rotation Procedure

```bash
# 1. Decrypt with old key
export SIGNALFORGE_DOTENV_KEY="old-passphrase"
php -r "
    \$env = \Signalforge\dotenv('.env.encrypted', ['export' => false]);
    foreach (\$env as \$k => \$v) {
        \$v = is_array(\$v) ? json_encode(\$v) : \$v;
        echo \"\$k=\$v\\n\";
    }
" > .env.tmp

# 2. Re-encrypt with new key
export SIGNALFORGE_DOTENV_KEY="new-strong-passphrase"
php encrypt-env.php .env.tmp .env.encrypted.new

# 3. Verify new file works
php -r "var_dump(\Signalforge\dotenv('.env.encrypted.new'));"

# 4. Replace old file
mv .env.encrypted.new .env.encrypted
rm .env.tmp

# 5. Update key in secret manager
```

## Troubleshooting

### Common Errors

| Error Message | Cause | Solution |
|---------------|-------|----------|
| "Encryption key required but not provided" | No key found in any source | Set `SIGNALFORGE_DOTENV_KEY` or pass `key` option |
| "Decryption failed: wrong key or tampered data" | Incorrect passphrase or corrupted file | Verify passphrase; re-encrypt if corrupted |
| "Data is not encrypted" | File missing magic bytes | Ensure file was encrypted with this extension |
| "Unsupported encryption format version" | File uses future format | Upgrade extension |

### Debugging

```php
<?php
// Check if file appears encrypted
$content = file_get_contents('.env.encrypted');
$isEncrypted = substr($content, 0, 8) === 'SFDOTENV';
echo "File is encrypted: " . ($isEncrypted ? "Yes" : "No") . "\n";

// Check version
if ($isEncrypted) {
    $version = ord($content[8]);
    echo "Format version: $version\n";
}

// Test decryption
try {
    $env = \Signalforge\dotenv('.env.encrypted', [
        'key' => getenv('SIGNALFORGE_DOTENV_KEY'),
        'export' => false,
    ]);
    echo "Decryption successful. Keys: " . implode(', ', array_keys($env)) . "\n";
} catch (\Signalforge\DotenvException $e) {
    echo "Decryption failed: " . $e->getMessage() . "\n";
    echo "Error code: " . $e->getCode() . "\n";
}
```

## API Reference

### Function Signature

```php
function \Signalforge\dotenv(string $path = '.env', array $options = []): array;
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `encrypted` | bool | auto | Force encrypted mode (auto-detects by default) |
| `key` | string | null | Encryption passphrase |
| `key_env` | string | null | Environment variable containing the key |
| `override` | bool | false | Override existing environment variables |
| `export` | bool | true | Inject into getenv() and $_ENV |
| `export_server` | bool | false | Also inject into $_SERVER |
| `arrays` | bool | true | Parse JSON arrays/objects |

### Exception Codes

| Code | Description |
|------|-------------|
| 1 | File not found or not readable |
| 2 | Error reading file contents |
| 3 | Syntax error in .env file |
| 4 | Decryption failed |
| 5 | Encrypted file but no key provided |
| 6 | Invalid key format |
| 7 | Memory allocation failed |
