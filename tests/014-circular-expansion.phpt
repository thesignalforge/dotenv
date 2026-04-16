--TEST--
Circular variable expansion is detected and does not hang
--EXTENSIONS--
signalforge_dotenv
--FILE--
<?php
$tmpDir = sys_get_temp_dir();
$envFile = $tmpDir . '/test_' . uniqid() . '.env';

// A -> B -> A is a direct cycle. Before the fix, expansion would recurse
// forever and hang the process. Now it must emit a warning and abort.
$content = <<<'ENV'
A=${B}
B=${A}
ENV;

file_put_contents($envFile, $content);

try {
    $result = @\Signalforge\dotenv($envFile, ['export' => false]);

    // The warning about circular reference must have fired.
    $err = error_get_last();
    var_dump($err !== null);
    var_dump(str_contains($err['message'] ?? '', 'circular'));

    // And the call must have completed, not hung.
    echo "COMPLETED\n";

} finally {
    unlink($envFile);
}

// Also test a longer indirect cycle: A -> B -> C -> A
$envFile2 = $tmpDir . '/test_' . uniqid() . '.env';
file_put_contents($envFile2, "A=\${B}\nB=\${C}\nC=\${A}\n");

try {
    error_clear_last();
    @\Signalforge\dotenv($envFile2, ['export' => false]);
    $err = error_get_last();
    var_dump($err !== null);
    var_dump(str_contains($err['message'] ?? '', 'circular'));
    echo "COMPLETED2\n";
} finally {
    unlink($envFile2);
}

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
COMPLETED
bool(true)
bool(true)
COMPLETED2
OK
