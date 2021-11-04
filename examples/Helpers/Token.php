<?php

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use CQ\Crypto\Helpers\Token;

try {
    $data = [
        'foo' => 'bar',
        'baz' => 'qux',
    ];

    $key = Token::generateKey();

    $encrypt = Token::encrypt(key: $key, data: $data);
    $decrypt = Token::decrypt(key: $key, token: $encrypt);
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'data' => $data,

    'key' => $key,

    'actions' => [
        'encrypt' => $encrypt,
        'decrypt' => $decrypt,
    ],
]);
