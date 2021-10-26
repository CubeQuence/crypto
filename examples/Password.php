<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\Password;

try {
    $string = 'Hello World!';

    $password = new Password();
    $password2 = new Password(key: $password->exportKey()); // Optionally provide key otherwise it will be generated

    // Different optional way of setting the key
    // $password2->setKey(key: $password->exportKey());

    $hash = $password->hash(plaintext: $string);
    $verify = $password2->verify(plaintext: $string, encryptedHash: $hash);
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,

    'key' => [
        'exportKey' => $password->exportKey(),
    ],

    'actions' => [
        'hash' => $hash,
        'verify' => $verify,
    ],
]);
