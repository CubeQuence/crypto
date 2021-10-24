<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\Exceptions\TokenException;
use CQ\Crypto\Token;




try {
    $data = [
        'foo' => 'bar',
        'baz' => 'qux',
    ];

    $token = new Token();
    $token2 = new Token(key: $token->exportKey()); // Optional method of setting the key

    $encrypt = $token->encrypt(data: $data);
    $decrypt = $token->decrypt(token: $encrypt);

    // TODO: sign
    // TODO: verify
} catch (TokenException $error) {
    echo 'Token invalid';
    exit;
} catch (\Throwable $error) {
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
        // 'sign' => $sign,
        // 'verify' => $verify,
    ]
]);
