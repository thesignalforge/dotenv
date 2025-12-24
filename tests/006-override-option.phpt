--TEST--
Override existing environment variables
--EXTENSIONS--
signalforge_dotenv
--FILE--
<?php
$tmpDir = sys_get_temp_dir();
$envFile = $tmpDir . '/test_' . uniqid() . '.env';
$uniqueKey = 'SIGNALFORGE_OVERRIDE_' . uniqid();

// Set initial value
putenv($uniqueKey . '=original');

$content = $uniqueKey . "=new_value\n";
file_put_contents($envFile, $content);

try {
    // Without override - should keep original
    \Signalforge\dotenv($envFile, ['export' => true, 'override' => false]);
    var_dump(getenv($uniqueKey) === 'original');

    // With override - should update
    \Signalforge\dotenv($envFile, ['export' => true, 'override' => true]);
    var_dump(getenv($uniqueKey) === 'new_value');

} finally {
    unlink($envFile);
}

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
OK
