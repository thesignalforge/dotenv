--TEST--
Encrypted file without key throws exception
--EXTENSIONS--
signalforge_dotenv
sodium
--FILE--
<?php
/**
 * Test that encrypted file without providing a key throws an exception.
 */

function encrypt_env(string $plaintext, string $passphrase): string {
    $magic = "SFDOTENV";
    $version = chr(0x01);
    $reserved = str_repeat(chr(0), 3);

    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    $key = sodium_crypto_pwhash(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
        $passphrase,
        $salt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );

    $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
    sodium_memzero($key);

    return $magic . $version . $reserved . $salt . $nonce . $ciphertext;
}

$tmpDir = sys_get_temp_dir();
$envFile = $tmpDir . '/test_nokey_' . uniqid() . '.env';
$passphrase = 'some-secret';

$plaintext = "SECRET=value\n";
$encrypted = encrypt_env($plaintext, $passphrase);
file_put_contents($envFile, $encrypted);

// Clear any environment variables that might provide a key
putenv('SIGNALFORGE_DOTENV_KEY');
putenv('DOTENV_PRIVATE_KEY');

try {
    try {
        $result = \Signalforge\dotenv($envFile, [
            'export' => false
            // No key provided
        ]);
        echo "ERROR: Should have thrown exception\n";
    } catch (\Signalforge\DotenvException $e) {
        var_dump(strpos($e->getMessage(), 'key required') !== false);
        echo "OK\n";
    }
} finally {
    unlink($envFile);
}
?>
--EXPECT--
bool(true)
OK
