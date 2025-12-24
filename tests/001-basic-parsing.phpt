--TEST--
Basic .env parsing
--EXTENSIONS--
signalforge_dotenv
--FILE--
<?php
// Create a temporary .env file
$tmpDir = sys_get_temp_dir();
$envFile = $tmpDir . '/test_' . uniqid() . '.env';

$content = <<<'ENV'
# Comment line
APP_NAME=MyApp
APP_ENV=production
DEBUG=false

# Quoted values
GREETING="Hello, World!"
SINGLE_QUOTED='literal $value'

# Empty value
EMPTY_VAR=
ENV;

file_put_contents($envFile, $content);

try {
    $result = \Signalforge\dotenv($envFile, ['export' => false]);

    var_dump(isset($result['APP_NAME']) && $result['APP_NAME'] === 'MyApp');
    var_dump(isset($result['APP_ENV']) && $result['APP_ENV'] === 'production');
    var_dump(isset($result['DEBUG']) && $result['DEBUG'] === 'false');
    var_dump(isset($result['GREETING']) && $result['GREETING'] === 'Hello, World!');
    var_dump(isset($result['SINGLE_QUOTED']) && $result['SINGLE_QUOTED'] === 'literal $value');
    var_dump(isset($result['EMPTY_VAR']) && $result['EMPTY_VAR'] === '');

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
