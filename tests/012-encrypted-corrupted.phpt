--TEST--
Corrupted encrypted file throws exception (tamper detection)
--EXTENSIONS--
signalforge_dotenv
sodium
--FILE--
<?php
/**
 * Test that tampered/corrupted encrypted file is detected.
 * XSalsa20-Poly1305 provides authenticated encryption - any modification
 * to the ciphertext will be detected.
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
$envFile = $tmpDir . '/test_corrupted_' . uniqid() . '.env';
$passphrase = 'test-key';

$plaintext = "SECRET=value\n";
$encrypted = encrypt_env($plaintext, $passphrase);

// Corrupt the ciphertext (flip a bit in the encrypted portion)
$headerSize = 8 + 1 + 3 + SODIUM_CRYPTO_PWHASH_SALTBYTES + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
$corrupted = $encrypted;
$corrupted[$headerSize + 5] = chr(ord($corrupted[$headerSize + 5]) ^ 0xFF);

file_put_contents($envFile, $corrupted);

try {
    try {
        $result = \Signalforge\dotenv($envFile, [
            'export' => false,
            'key' => $passphrase
        ]);
        echo "ERROR: Should have thrown exception\n";
    } catch (\Signalforge\DotenvException $e) {
        // Should detect tampering and fail decryption
        var_dump(strpos($e->getMessage(), 'Decryption failed') !== false);
        echo "OK\n";
    }
} finally {
    unlink($envFile);
}
?>
--EXPECT--
bool(true)
OK
