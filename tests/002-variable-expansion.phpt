--TEST--
Variable expansion in .env values
--EXTENSIONS--
signalforge_dotenv
--FILE--
<?php
$tmpDir = sys_get_temp_dir();
$envFile = $tmpDir . '/test_' . uniqid() . '.env';

$content = <<<'ENV'
BASE_URL=https://example.com
API_URL=${BASE_URL}/api
DEFAULT_PORT=${UNDEFINED_VAR:-8080}
ALTERNATE=${BASE_URL:+found}
SIMPLE=$BASE_URL
ENV;

file_put_contents($envFile, $content);

try {
    $result = \Signalforge\dotenv($envFile, ['export' => false]);

    var_dump($result['BASE_URL'] === 'https://example.com');
    var_dump($result['API_URL'] === 'https://example.com/api');
    var_dump($result['DEFAULT_PORT'] === '8080');
    var_dump($result['ALTERNATE'] === 'found');
    var_dump($result['SIMPLE'] === 'https://example.com');

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
OK
