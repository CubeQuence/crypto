<?php

declare(strict_types=1);

use CQ\Crypto\Token;

$key = random_bytes(32);

$token = Token::create(
    key: $key,
    data: [
        'foo' => 'bar',
    ]
);

$decode = Token::decode(
    key: $key,
    givenToken: $token
);

echo json_encode([
    'token' => $token,
    'isValid' => $decode,
]);
