--TEST--
Encrypted file with wrong passphrase throws exception
--EXTENSIONS--
signalforge_dotenv
sodium
--FILE--
<?php
/**
 * Test that decryption with wrong key throws an exception.
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
$envFile = $tmpDir . '/test_wrongkey_' . uniqid() . '.env';
$correctKey = 'correct-passphrase';
$wrongKey = 'wrong-passphrase';

$plaintext = "SECRET=value\n";
$encrypted = encrypt_env($plaintext, $correctKey);
file_put_contents($envFile, $encrypted);

try {
    try {
        $result = \Signalforge\dotenv($envFile, [
            'export' => false,
            'key' => $wrongKey
        ]);
        echo "ERROR: Should have thrown exception\n";
    } catch (\Signalforge\DotenvException $e) {
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
