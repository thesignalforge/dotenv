--TEST--
Basic encrypted .env file decryption
--EXTENSIONS--
signalforge_dotenv
sodium
--FILE--
<?php
/**
 * Test basic encrypted file decryption.
 * Creates an encrypted .env file using the same format as the C extension.
 */

// Create encrypted file using PHP sodium (matching C extension format)
function encrypt_env(string $plaintext, string $passphrase): string {
    $magic = "SFDOTENV";
    $version = chr(0x01);
    $reserved = str_repeat(chr(0), 3);

    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    // Derive key using Argon2id (matching C extension parameters)
    $key = sodium_crypto_pwhash(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
        $passphrase,
        $salt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );

    // Encrypt with XSalsa20-Poly1305
    $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

    // Secure cleanup
    sodium_memzero($key);

    return $magic . $version . $reserved . $salt . $nonce . $ciphertext;
}

$tmpDir = sys_get_temp_dir();
$envFile = $tmpDir . '/test_encrypted_' . uniqid() . '.env';
$passphrase = 'test-secret-key-123';

$plaintext = <<<'ENV'
DB_HOST=localhost
DB_PORT=5432
DB_USER=admin
DB_PASS=supersecret
ENV;

$encrypted = encrypt_env($plaintext, $passphrase);
file_put_contents($envFile, $encrypted);

try {
    $result = \Signalforge\dotenv($envFile, [
        'export' => false,
        'key' => $passphrase
    ]);

    var_dump($result['DB_HOST'] === 'localhost');
    var_dump($result['DB_PORT'] === '5432');
    var_dump($result['DB_USER'] === 'admin');
    var_dump($result['DB_PASS'] === 'supersecret');

    echo "OK\n";
} finally {
    unlink($envFile);
}
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
OK
