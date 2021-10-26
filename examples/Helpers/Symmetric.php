<?php

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use CQ\Crypto\Helpers\Symmetric;

try {
    $string = 'Hello World!';
    $key = Symmetric::generateKey();

    $encrypt = Symmetric::encrypt(key: $key, plaintext: $string);
    $decrypt = Symmetric::decrypt(key: $key, ciphertext: $encrypt);

    $sign = Symmetric::sign(key: $key, plaintext: $string);
    $verify = Symmetric::verify(key: $key, plaintext: $string, signature: $sign);
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'key' => $key,

    'actions' => [
        'encrypt' => $encrypt,
        'decrypt' => $decrypt,
        'sign' => $sign,
        'verify' => $verify,
    ],
]);
