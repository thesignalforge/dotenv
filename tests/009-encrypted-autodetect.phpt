--TEST--
Auto-detection of encrypted .env files
--EXTENSIONS--
signalforge_dotenv
sodium
--FILE--
<?php
/**
 * Test that encrypted files are auto-detected by magic bytes.
 * No 'encrypted' option needed when file has SFDOTENV header.
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
$envFile = $tmpDir . '/test_autodetect_' . uniqid() . '.env';
$passphrase = 'auto-detect-test-key';

$plaintext = <<<'ENV'
API_KEY=secret123
API_SECRET=topsecret456
ENV;

$encrypted = encrypt_env($plaintext, $passphrase);
file_put_contents($envFile, $encrypted);

try {
    // Test auto-detection without 'encrypted' option
    $result = \Signalforge\dotenv($envFile, [
        'export' => false,
        'key' => $passphrase
        // Note: no 'encrypted' option - should auto-detect
    ]);

    var_dump($result['API_KEY'] === 'secret123');
    var_dump($result['API_SECRET'] === 'topsecret456');

    echo "OK\n";
} finally {
    unlink($envFile);
}
?>
--EXPECT--
bool(true)
bool(true)
OK
