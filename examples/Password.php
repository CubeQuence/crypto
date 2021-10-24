<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\Password;
use CQ\Crypto\Symmetric;

try {
    $string = 'Hello World!';

    // TODO: make cleaner syntax

    $symmetric = new Symmetric();
    $key = $symmetric->exportKey();

    // Optionally provide key otherwise it will be generated
    $password = new Password(key: $key);

    $encryptedHash = $password->hash(plaintext: $string);
    $verify = $password->verify(plaintext: $string, encryptedHash: $encryptedHash);
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'encryptedHash' => $encryptedHash,
    'verify' => $verify,
]);
