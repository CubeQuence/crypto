<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\Symmetric;

try {
    $string = 'Hello World!';

    $symmetric = new Symmetric();
    $symmetric2 = new Symmetric(key: $symmetric->exportKey()); // Optional method of setting the key

    // Different optional way of setting the key
    // $symmetric2->setKey(key: $symmetric->exportKey());

    $encrypt = $symmetric->encrypt(plaintext: $string);
    $decrypt = $symmetric2->decrypt(ciphertext: $encrypt);

    $sign = $symmetric->sign(plaintext: $string);
    $verify = $symmetric2->verify(plaintext: $string, signature: $sign);
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,

    'key' => [
        'exportKey' => $symmetric->exportKey(),
    ],

    'actions' => [
        'encrypt' => $encrypt,
        'decrypt' => $decrypt,
        'sign' => $sign,
        'verify' => $verify,
    ],
]);
