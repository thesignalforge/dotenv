# Signalforge Dotenv Extension

A high-performance PHP C extension for loading, parsing, and decrypting `.env` files.

## Quick Start

```php
<?php
// Load .env from current directory
$env = \Signalforge\dotenv();

// Access values
echo $env['APP_NAME'];
echo getenv('APP_NAME');
echo $_ENV['APP_NAME'];
```

## Examples

### Loading from Different Paths

```php
// Load from specific path
$env = \Signalforge\dotenv('/path/to/.env');

// Load from multiple files (later files override earlier)
$env = \Signalforge\dotenv(['.env', '.env.local']);
```

### Variable Expansion with Defaults

```php
// .env file:
// BASE_URL=https://api.example.com
// API_ENDPOINT=${BASE_URL}/v2
// LOG_LEVEL=${LOG_LEVEL:-info}
// DEBUG_MODE=${DEBUG:+enabled}

$env = \Signalforge\dotenv();

echo $env['API_ENDPOINT'];  // https://api.example.com/v2
echo $env['LOG_LEVEL'];     // "info" (default, since LOG_LEVEL wasn't set)
echo $env['DEBUG_MODE'];    // "" (empty, since DEBUG wasn't set)
```

### Encrypted Values with Defaults

```php
// .env file:
// SECRET_KEY=encrypted:base64data...
// FALLBACK_SECRET=${SECRET_KEY:-default-dev-key}
// API_KEY=${API_KEY:-${SECRET_KEY}}

$env = \Signalforge\dotenv('.env', [
    'encrypted' => true,
    'key_env' => 'DOTENV_KEY',
]);

// SECRET_KEY is decrypted automatically
// FALLBACK_SECRET uses SECRET_KEY if decryption succeeds, otherwise "default-dev-key"
// API_KEY uses env var if set, otherwise falls back to SECRET_KEY
```

### JSON Values

```php
// .env file:
// ALLOWED_HOSTS=["localhost", "127.0.0.1", "example.com"]
// DB_CONFIG={"host": "localhost", "port": 5432, "ssl": true}
// FEATURE_FLAGS={"dark_mode": true, "beta": false}

$env = \Signalforge\dotenv('.env', ['arrays' => true]);

// $env['ALLOWED_HOSTS'] is now a PHP array
foreach ($env['ALLOWED_HOSTS'] as $host) {
    echo "Allowed: $host\n";
}

// $env['DB_CONFIG'] is now a PHP associative array
$dsn = "pgsql:host={$env['DB_CONFIG']['host']};port={$env['DB_CONFIG']['port']}";
```

### Encrypted Files

```bash
# Set encryption key via environment
export SIGNALFORGE_DOTENV_KEY="your-secure-passphrase"
```

```php
// Key is automatically read from SIGNALFORGE_DOTENV_KEY
$env = \Signalforge\dotenv('.env.encrypted', [
    'encrypted' => true,
]);

// Or specify key source explicitly
$env = \Signalforge\dotenv('.env.encrypted', [
    'encrypted' => true,
    'key_env' => 'MY_CUSTOM_KEY_VAR',
]);
```

### Override Existing Environment Variables

```php
// By default, existing env vars are NOT overwritten
$env = \Signalforge\dotenv('.env');

// Force override of existing values
$env = \Signalforge\dotenv('.env', ['override' => true]);
```

### Control Export Behavior

```php
// Export to getenv() and $_ENV (default)
$env = \Signalforge\dotenv('.env', ['export' => true]);

// Also export to $_SERVER
$env = \Signalforge\dotenv('.env', [
    'export' => true,
    'export_server' => true,
]);

// Parse only, don't modify environment
$env = \Signalforge\dotenv('.env', ['export' => false]);
```

### Swoole / Long-Running Processes

```php
// Load once at worker start
$env = \Signalforge\dotenv('.env');

// Store in your config
Config::setEnv($env);

// Reload on demand (e.g., SIGHUP handler)
pcntl_signal(SIGHUP, function() {
    Config::setEnv(\Signalforge\dotenv('.env', ['override' => true]));
});
```

### Combined Example

```php
// Production-ready configuration
$env = \Signalforge\dotenv('.env', [
    'encrypted' => true,
    'key_env' => 'DOTENV_KEY',
    'override' => false,
    'export' => true,
    'export_server' => false,
    'arrays' => true,
]);

// Access decrypted database credentials with fallback
$dbHost = $env['DB_HOST'] ?? 'localhost';
$dbPort = $env['DB_PORT'] ?? 5432;
$dbPass = $env['DB_PASSWORD'];  // Decrypted automatically
```

## Features

- **Fast Parsing**: Single-pass state machine parser, significantly faster than userland PHP implementations
- **Standard Format**: Compatible with standard dotenv syntax (quotes, comments, multiline)
- **Variable Expansion**: Full support for `${VAR}`, `${VAR:-default}`, `${VAR:+alternate}`
- **JSON Values**: Automatic parsing of JSON arrays and objects
- **Encryption**: Authenticated encryption using libsodium (Argon2id + XSalsa20-Poly1305)
- **Environment Injection**: Injects into `getenv()`, `$_ENV`, and optionally `$_SERVER`
- **Runtime Safe**: Works correctly in CLI, PHP-FPM, and Swoole environments

## Requirements

- PHP 8.5+
- libsodium-dev (usually included with PHP)
- Standard build tools (gcc, make, autoconf)

## Installation

### From Source

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install php-dev libsodium-dev

# Build
cd /path/to/signalforge_dotenv
phpize
./configure --enable-signalforge-dotenv
make
sudo make install

# Enable extension
echo "extension=signalforge_dotenv.so" | sudo tee /etc/php/8.5/mods-available/signalforge_dotenv.ini
sudo phpenmod signalforge_dotenv
```

### Verify Installation

```bash
php -m | grep signalforge_dotenv
php --ri signalforge_dotenv
```

## Options Reference

```php
$env = \Signalforge\dotenv('.env', [
    'encrypted' => false,       // true = expect encrypted file
    'key' => null,              // Encryption passphrase
    'key_env' => null,          // Env var containing the key
    'override' => false,        // Override existing env vars
    'export' => true,           // Export to getenv()/$_ENV
    'export_server' => false,   // Also export to $_SERVER
    'format' => 'auto',         // 'auto', 'plain', 'json'
    'arrays' => true,           // Parse JSON arrays/objects
]);
```

## .env File Format

```ini
# Comments start with #
KEY=value

# Quoted values
QUOTED="with spaces and $expansion"
LITERAL='no $expansion here'

# Multiline (double quotes or backticks)
MULTILINE="line1
line2"

# Escape sequences (double quotes only)
ESCAPED="tab:\t newline:\n"

# Empty value
EMPTY=

# Variable expansion
BASE_URL=https://example.com
API_URL=${BASE_URL}/api

# Default values
LOG_LEVEL=${LOG_LEVEL:-info}
TIMEOUT=${TIMEOUT:-30}

# Alternate values (use if set)
DEBUG_FLAG=${DEBUG:+--verbose}

# JSON values
ARRAY=["a", "b", "c"]
OBJECT={"key": "value"}
```

## Encryption Format

The extension uses a custom encryption format optimized for security:

```
+------------------+
| Magic (8 bytes)  |  "SFDOTENV"
+------------------+
| Version (1 byte) |  0x01
+------------------+
| Reserved (3 b)   |
+------------------+
| Salt (16 bytes)  |  For Argon2id KDF
+------------------+
| Nonce (24 bytes) |  For XSalsa20
+------------------+
| Ciphertext       |  Encrypted + Poly1305 MAC
+------------------+
```

**Algorithms:**
- Key Derivation: Argon2id (moderate settings)
- Encryption: XSalsa20-Poly1305 (libsodium secretbox)

## Build & Test

```bash
# Build
phpize
./configure --enable-signalforge-dotenv
make

# Run tests
make test

# Clean build
make clean
phpize --clean
```

## Security Notes

### Key Management

1. **Never hardcode keys**: Use environment variables or secret managers
2. **Key rotation**: Re-encrypt files periodically with new keys
3. **Minimum key length**: Use passphrases of at least 16 characters
4. **Separate keys**: Use different keys for different environments

### Best Practices

```php
// DON'T: Hardcode keys
$env = \Signalforge\dotenv('.env', ['key' => 'my-secret']);

// DO: Use environment variables
$env = \Signalforge\dotenv('.env', ['key_env' => 'DOTENV_KEY']);

// DON'T: Log decrypted values
error_log(print_r($env, true));

// DO: Only log non-sensitive info
error_log("Loaded " . count($env) . " environment variables");

// DON'T: Export to $_SERVER in shared hosting
$env = \Signalforge\dotenv('.env', ['export_server' => true]);

// DO: Minimize exposure
$env = \Signalforge\dotenv('.env', ['export' => true, 'export_server' => false]);
```

### Threat Model

**Protected against:**
- Unauthorized file access (encrypted files are safe to commit)
- Tampering (authenticated encryption detects modifications)
- Brute-force attacks on weak passwords (Argon2id)

**Not protected against:**
- Compromised encryption key
- Memory inspection of running process
- Root/admin access to the server

## API Reference

### `\Signalforge\dotenv(string $path = '.env', array $options = []): array`

Loads and parses a .env file, optionally decrypting it.

**Parameters:**
- `$path`: Path to the .env file
- `$options`: Configuration array (see Options Reference)

**Returns:** Associative array of parsed key-value pairs

**Throws:** `\Signalforge\DotenvException` on error

### Exception Codes

| Code | Description |
|------|-------------|
| 1 | File not found |
| 2 | File read error |
| 3 | Parse error |
| 4 | Decryption error |
| 5 | Key required but not provided |
| 6 | Invalid key format |
| 7 | Memory allocation error |
| 8 | JSON parse error |
| 9 | Crypto initialization error |

## License

MIT License - See LICENSE file

## Contributing

Contributions are welcome. Please ensure:
1. Code compiles without warnings (`-Wall -Wextra`)
2. All tests pass (`make test`)
3. Memory is properly managed (use valgrind)
4. Security implications are considered
