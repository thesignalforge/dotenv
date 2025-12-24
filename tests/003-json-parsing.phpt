--TEST--
JSON value parsing
--EXTENSIONS--
signalforge_dotenv
--FILE--
<?php
$tmpDir = sys_get_temp_dir();
$envFile = $tmpDir . '/test_' . uniqid() . '.env';

$content = <<<'ENV'
JSON_ARRAY=["one", "two", "three"]
JSON_OBJECT={"key": "value", "number": 42}
PLAIN_STRING=not json
ENV;

file_put_contents($envFile, $content);

try {
    $result = \Signalforge\dotenv($envFile, ['export' => false, 'arrays' => true]);

    var_dump(is_array($result['JSON_ARRAY']));
    var_dump($result['JSON_ARRAY'] === ['one', 'two', 'three']);
    var_dump(is_array($result['JSON_OBJECT']));
    var_dump($result['JSON_OBJECT']['key'] === 'value');
    var_dump($result['JSON_OBJECT']['number'] === 42);
    var_dump(is_string($result['PLAIN_STRING']));

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
bool(true)
bool(true)
OK
