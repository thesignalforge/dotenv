--TEST--
Environment variable injection
--EXTENSIONS--
signalforge_dotenv
--FILE--
<?php
$tmpDir = sys_get_temp_dir();
$envFile = $tmpDir . '/test_' . uniqid() . '.env';
$uniqueKey = 'SIGNALFORGE_TEST_' . uniqid();

$content = $uniqueKey . "=test_value\n";
file_put_contents($envFile, $content);

try {
    $result = \Signalforge\dotenv($envFile, ['export' => true]);

    // Check getenv
    var_dump(getenv($uniqueKey) === 'test_value');

    // Check $_ENV
    var_dump(isset($_ENV[$uniqueKey]) && $_ENV[$uniqueKey] === 'test_value');

} finally {
    unlink($envFile);
}

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
OK
