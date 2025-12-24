--TEST--
Encrypted file with key from environment variable
--EXTENSIONS--
signalforge_dotenv
sodium
--FILE--
<?php
/**
 * Test reading encryption key from environment variable using key_env option.
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
$envFile = $tmpDir . '/test_keyenv_' . uniqid() . '.env';
$passphrase = 'env-var-secret-key';

$plaintext = <<<'ENV'
DATABASE_URL=postgres://user:pass@localhost/db
REDIS_URL=redis://localhost:6379
ENV;

$encrypted = encrypt_env($plaintext, $passphrase);
file_put_contents($envFile, $encrypted);

// Set the key in a custom environment variable
putenv('MY_CUSTOM_KEY=' . $passphrase);

try {
    $result = \Signalforge\dotenv($envFile, [
        'export' => false,
        'key_env' => 'MY_CUSTOM_KEY'
    ]);

    var_dump($result['DATABASE_URL'] === 'postgres://user:pass@localhost/db');
    var_dump($result['REDIS_URL'] === 'redis://localhost:6379');

    echo "OK\n";
} finally {
    unlink($envFile);
    putenv('MY_CUSTOM_KEY');
}
?>
--EXPECT--
bool(true)
bool(true)
OK
