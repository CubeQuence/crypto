<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\Hash;

try {
    $string = 'Hello World!';

    $hash = Hash::make(string: $string);
    $verify = Hash::verify(string: $string, hash: $hash);
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'hash' => $hash,
    'verify' => $verify,
]);
