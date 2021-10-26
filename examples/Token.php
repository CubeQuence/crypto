<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\Exceptions\CryptoException;
use CQ\Crypto\Token;

try {
    $data = [
        'foo' => 'bar',
        'baz' => 'qux',
    ];

    $token = new Token();
    $token2 = new Token(key: $token->exportKey()); // Optional method of setting the key

    // Different optional way of setting the key
    // $token2->setKey(key: $token->exportKey());

    $encrypt = $token->encrypt(data: $data);
    $decrypt = $token2->decrypt(token: $encrypt);
} catch (CryptoException $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'data' => $data,

    'key' => [
        'exportKey' => $token->exportKey(),
    ],

    'actions' => [
        'encrypt' => $encrypt,
        'decrypt' => $decrypt,
    ]
]);
