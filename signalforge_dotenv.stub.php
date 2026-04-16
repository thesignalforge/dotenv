<?php
/**
 * Dotenv Extension for Signalforge Framework
 *
 * Loads and parses `.env` files written in C for performance and safety.
 * Supports plain and authenticated/encrypted (.env.enc) files, variable
 * expansion, JSON-typed values, and injection into the process environment
 * (getenv / $_ENV / optionally $_SERVER).
 *
 * @version 1.0.0
 * @package Signalforge
 */

declare(strict_types=1);

namespace Signalforge;

/**
 * Exception thrown by the dotenv extension.
 *
 * Codes correspond to the SF_DOTENV_ERR_* constants emitted by the C
 * implementation: file not found, missing/invalid encryption key, decrypt
 * failure, parse error, etc.
 */
class DotenvException extends \Exception
{
}

/**
 * Load and parse a .env file.
 *
 * Reads the file, optionally decrypts it (auto-detected by header magic
 * unless overridden), parses key=value pairs, expands referenced variables,
 * optionally JSON-decodes array/object literals, and (by default) exports
 * the resulting variables into the process environment.
 *
 * The returned array contains the parsed and expanded values regardless of
 * whether export is enabled.
 *
 * Recognized option keys:
 *  - `encrypted`   (bool)   Force encrypted decoding. Disables auto-detect.
 *  - `key`         (string) Symmetric key material to use for decryption.
 *  - `key_env`     (string) Name of an environment variable holding the key.
 *  - `override`    (bool)   Overwrite existing env vars (default false).
 *  - `export`      (bool)   Inject into getenv()/$_ENV (default true).
 *  - `export_server` (bool) Also inject into $_SERVER (default false).
 *  - `format`      (string) Reserved for forward compatibility.
 *  - `arrays`      (bool)   Try JSON-parse values into arrays (default true).
 *
 * If `key` and `key_env` are absent, the extension consults the
 * `SIGNALFORGE_DOTENV_KEY` and `DOTENV_PRIVATE_KEY` environment variables
 * before failing with `DotenvException`.
 *
 * @param string $path Path to the .env file (default ".env")
 * @param array $options Loader options (see list above)
 * @return array<string, mixed> Parsed and expanded values
 * @throws DotenvException On missing file, missing key, decrypt failure or parse error
 *
 * @example
 * $vars = \Signalforge\dotenv('.env');
 *
 * @example
 * // Encrypted file with key from environment
 * $vars = \Signalforge\dotenv('.env.enc', [
 *     'key_env' => 'APP_DOTENV_KEY',
 *     'override' => true,
 * ]);
 */
function dotenv(string $path = '.env', array $options = []): array {}
