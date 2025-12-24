--TEST--
Multiline values and escape sequences
--EXTENSIONS--
signalforge_dotenv
--FILE--
<?php
$tmpDir = sys_get_temp_dir();
$envFile = $tmpDir . '/test_' . uniqid() . '.env';

$content = <<<'ENV'
MULTILINE="line1
line2
line3"
ESCAPED="tab:\there\nnewline"
QUOTES="say \"hello\""
ENV;

file_put_contents($envFile, $content);

try {
    $result = \Signalforge\dotenv($envFile, ['export' => false]);

    var_dump(strpos($result['MULTILINE'], "\n") !== false);
    var_dump(strpos($result['ESCAPED'], "\t") !== false);
    var_dump(strpos($result['ESCAPED'], "\n") !== false);
    var_dump(strpos($result['QUOTES'], '"') !== false);

} finally {
    unlink($envFile);
}

echo "OK\n";
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
OK
