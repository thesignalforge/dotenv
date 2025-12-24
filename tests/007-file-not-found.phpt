--TEST--
Exception on file not found
--EXTENSIONS--
signalforge_dotenv
--FILE--
<?php
try {
    \Signalforge\dotenv('/nonexistent/path/.env');
    echo "No exception thrown\n";
} catch (\Signalforge\DotenvException $e) {
    echo "Exception: " . (strpos($e->getMessage(), 'Failed to read file') !== false ? 'OK' : 'FAIL') . "\n";
}
?>
--EXPECT--
Exception: OK
