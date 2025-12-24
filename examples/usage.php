#!/usr/bin/env php
<?php
/**
 * Signalforge Dotenv Extension - Usage Examples
 *
 * This file demonstrates the various features of the signalforge_dotenv extension.
 */

declare(strict_types=1);

// Check if extension is loaded
if (!extension_loaded('signalforge_dotenv')) {
    die("Error: signalforge_dotenv extension is not loaded.\n");
}

echo "Signalforge Dotenv Extension Examples\n";
echo "======================================\n\n";

// Create temporary .env files for demonstration
$tmpDir = sys_get_temp_dir();

// -----------------------------------------------------------------------------
// Example 1: Basic Usage
// -----------------------------------------------------------------------------
echo "1. Basic Usage\n";
echo "--------------\n";

$basicEnv = $tmpDir . '/example_basic.env';
file_put_contents($basicEnv, <<<'ENV'
# Application settings
APP_NAME=MyApp
APP_ENV=development
APP_DEBUG=true

# Database configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=myapp
ENV
);

try {
    $env = \Signalforge\dotenv($basicEnv);

    echo "Loaded " . count($env) . " variables:\n";
    foreach ($env as $key => $value) {
        echo "  $key = $value\n";
    }
    echo "\n";

    // Values are also available via getenv()
    echo "getenv('APP_NAME') = " . getenv('APP_NAME') . "\n\n";

} finally {
    unlink($basicEnv);
}

// -----------------------------------------------------------------------------
// Example 2: Variable Expansion
// -----------------------------------------------------------------------------
echo "2. Variable Expansion\n";
echo "---------------------\n";

$expansionEnv = $tmpDir . '/example_expansion.env';
file_put_contents($expansionEnv, <<<'ENV'
BASE_URL=https://api.example.com
API_VERSION=v2
API_ENDPOINT=${BASE_URL}/${API_VERSION}

# Default values
LOG_LEVEL=${UNDEFINED_VAR:-info}

# Reference existing environment
USER_HOME=${HOME}
ENV
);

try {
    $env = \Signalforge\dotenv($expansionEnv, ['export' => false]);

    echo "API_ENDPOINT = " . $env['API_ENDPOINT'] . "\n";
    echo "LOG_LEVEL = " . $env['LOG_LEVEL'] . " (with default)\n";
    echo "USER_HOME = " . $env['USER_HOME'] . " (from system)\n\n";

} finally {
    unlink($expansionEnv);
}

// -----------------------------------------------------------------------------
// Example 3: JSON Values
// -----------------------------------------------------------------------------
echo "3. JSON Array/Object Values\n";
echo "---------------------------\n";

$jsonEnv = $tmpDir . '/example_json.env';
file_put_contents($jsonEnv, <<<'ENV'
ALLOWED_HOSTS=["localhost", "127.0.0.1", "example.com"]
DATABASE_CONFIG={"host": "localhost", "port": 5432, "ssl": true}
SIMPLE_LIST=one,two,three
ENV
);

try {
    $env = \Signalforge\dotenv($jsonEnv, ['export' => false, 'arrays' => true]);

    echo "ALLOWED_HOSTS (array): " . print_r($env['ALLOWED_HOSTS'], true);
    echo "DATABASE_CONFIG (array): " . print_r($env['DATABASE_CONFIG'], true);
    echo "SIMPLE_LIST (string): " . $env['SIMPLE_LIST'] . "\n\n";

} finally {
    unlink($jsonEnv);
}

// -----------------------------------------------------------------------------
// Example 4: Options
// -----------------------------------------------------------------------------
echo "4. Configuration Options\n";
echo "------------------------\n";

$optionsEnv = $tmpDir . '/example_options.env';
file_put_contents($optionsEnv, 'TEST_VAR=from_file');

// Pre-set an environment variable
putenv('TEST_VAR=from_system');

try {
    // Without override (default)
    $env1 = \Signalforge\dotenv($optionsEnv, ['override' => false, 'export' => false]);
    echo "Without override: TEST_VAR = " . getenv('TEST_VAR') . "\n";

    // With override
    $env2 = \Signalforge\dotenv($optionsEnv, ['override' => true]);
    echo "With override: TEST_VAR = " . getenv('TEST_VAR') . "\n\n";

} finally {
    unlink($optionsEnv);
}

// -----------------------------------------------------------------------------
// Example 5: Multiple Quote Styles
// -----------------------------------------------------------------------------
echo "5. Quote Styles\n";
echo "---------------\n";

$quotesEnv = $tmpDir . '/example_quotes.env';
file_put_contents($quotesEnv, <<<'ENV'
UNQUOTED=simple value
DOUBLE_QUOTED="with spaces and ${BASE_URL:-default} expansion"
SINGLE_QUOTED='literal ${NO_EXPANSION} here'
BACKTICK=`multiline
supported`
ENV
);

try {
    $env = \Signalforge\dotenv($quotesEnv, ['export' => false]);

    foreach ($env as $key => $value) {
        $display = str_replace("\n", "\\n", $value);
        echo "  $key = \"$display\"\n";
    }
    echo "\n";

} finally {
    unlink($quotesEnv);
}

// -----------------------------------------------------------------------------
// Example 6: Error Handling
// -----------------------------------------------------------------------------
echo "6. Error Handling\n";
echo "-----------------\n";

try {
    \Signalforge\dotenv('/nonexistent/.env');
} catch (\Signalforge\DotenvException $e) {
    echo "Caught exception: " . $e->getMessage() . "\n";
}

echo "\n";

// -----------------------------------------------------------------------------
// Example 7: Swoole/Long-Running Process Pattern
// -----------------------------------------------------------------------------
echo "7. Swoole/Long-Running Pattern\n";
echo "------------------------------\n";

echo <<<'INFO'
For Swoole or other long-running processes, you should:

1. Load env ONCE at startup:
   $env = \Signalforge\dotenv('.env');

2. Store in a static property or dependency container:
   Config::set('env', $env);

3. Access without re-parsing:
   $value = Config::get('env')['DB_HOST'];

4. To reload (e.g., on SIGHUP):
   Config::set('env', \Signalforge\dotenv('.env', ['override' => true]));

INFO;

echo "\n";

// -----------------------------------------------------------------------------
// Example 8: CLI Decryption Tool Pattern
// -----------------------------------------------------------------------------
echo "8. CLI Decryption Pattern\n";
echo "-------------------------\n";

echo <<<'INFO'
For CLI tools that need to decrypt and display values:

$env = \Signalforge\dotenv('.env.encrypted', [
    'encrypted' => true,
    'key' => getenv('DOTENV_KEY'),  // Key from environment
    'export' => false               // Don't pollute environment
]);

// Display securely (never echo to logs)
foreach ($env as $key => $value) {
    echo "$key=" . str_repeat('*', min(strlen($value), 10)) . "\n";
}

INFO;

echo "\nDone!\n";
