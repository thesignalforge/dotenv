#!/usr/bin/env php
<?php
/**
 * Signalforge Dotenv - CLI Encryption Tool
 *
 * Usage:
 *   php encrypt-cli.php encrypt <input.env> <output.env.enc> [passphrase]
 *   php encrypt-cli.php decrypt <input.env.enc> <output.env> [passphrase]
 *   php encrypt-cli.php view <file.env.enc> [passphrase]
 *
 * If passphrase is not provided, it will be read from SIGNALFORGE_DOTENV_KEY
 * environment variable or prompted interactively.
 */

declare(strict_types=1);

if (!extension_loaded('signalforge_dotenv')) {
    fwrite(STDERR, "Error: signalforge_dotenv extension is not loaded.\n");
    exit(1);
}

/**
 * Since the extension doesn't expose encrypt() directly to PHP,
 * this is a demonstration of how you would implement a CLI tool
 * once that functionality is added.
 *
 * For now, this shows the decryption workflow.
 */

function usage(): void
{
    $script = basename($_SERVER['argv'][0]);
    echo <<<USAGE
Signalforge Dotenv CLI Tool

Usage:
  $script view <file.env.enc> [passphrase]    View decrypted contents
  $script load <file.env> [options]           Load and display env file

Options:
  passphrase    Encryption passphrase (or set SIGNALFORGE_DOTENV_KEY)

Examples:
  $script view .env.encrypted
  $script load .env
  SIGNALFORGE_DOTENV_KEY=secret $script view .env.enc

USAGE;
}

function get_passphrase(?string $arg): string
{
    if ($arg !== null) {
        return $arg;
    }

    $key = getenv('SIGNALFORGE_DOTENV_KEY');
    if ($key !== false && $key !== '') {
        return $key;
    }

    // Interactive prompt
    if (function_exists('readline')) {
        fwrite(STDERR, "Enter passphrase: ");
        system('stty -echo');
        $pass = readline();
        system('stty echo');
        fwrite(STDERR, "\n");
        return $pass;
    }

    fwrite(STDERR, "Error: No passphrase provided and cannot prompt.\n");
    fwrite(STDERR, "Set SIGNALFORGE_DOTENV_KEY or pass as argument.\n");
    exit(1);
}

function cmd_view(string $file, ?string $passphrase): void
{
    if (!file_exists($file)) {
        fwrite(STDERR, "Error: File not found: $file\n");
        exit(1);
    }

    $key = get_passphrase($passphrase);

    try {
        $env = \Signalforge\dotenv($file, [
            'encrypted' => true,
            'key' => $key,
            'export' => false,
        ]);

        echo "# Decrypted contents of $file\n";
        echo "# WARNING: Contains sensitive data\n\n";

        foreach ($env as $name => $value) {
            if (is_array($value)) {
                $value = json_encode($value, JSON_UNESCAPED_SLASHES);
            }
            // Escape for shell-safe output
            if (preg_match('/[\s"\'$`\\\\]/', $value)) {
                $value = '"' . addcslashes($value, '"$`\\') . '"';
            }
            echo "$name=$value\n";
        }

    } catch (\Signalforge\DotenvException $e) {
        fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
        exit(1);
    }
}

function cmd_load(string $file): void
{
    if (!file_exists($file)) {
        fwrite(STDERR, "Error: File not found: $file\n");
        exit(1);
    }

    try {
        $env = \Signalforge\dotenv($file, [
            'export' => false,
        ]);

        echo "# Contents of $file\n\n";

        foreach ($env as $name => $value) {
            if (is_array($value)) {
                $value = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
                echo "$name=" . str_replace("\n", "\n  ", $value) . "\n";
            } else {
                if (preg_match('/[\s"\'$`\\\\]/', $value)) {
                    $value = '"' . addcslashes($value, '"$`\\') . '"';
                }
                echo "$name=$value\n";
            }
        }

    } catch (\Signalforge\DotenvException $e) {
        fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
        exit(1);
    }
}

// Main
$argv = $_SERVER['argv'];
$argc = count($argv);

if ($argc < 2) {
    usage();
    exit(0);
}

$command = $argv[1];

switch ($command) {
    case 'view':
        if ($argc < 3) {
            fwrite(STDERR, "Error: Missing file argument\n");
            usage();
            exit(1);
        }
        cmd_view($argv[2], $argv[3] ?? null);
        break;

    case 'load':
        if ($argc < 3) {
            fwrite(STDERR, "Error: Missing file argument\n");
            usage();
            exit(1);
        }
        cmd_load($argv[2]);
        break;

    case 'help':
    case '--help':
    case '-h':
        usage();
        break;

    default:
        fwrite(STDERR, "Error: Unknown command: $command\n");
        usage();
        exit(1);
}
