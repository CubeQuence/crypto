<?php

declare(strict_types=1);

use CQ\Crypto\Exceptions\TokenException;
use CQ\Crypto\Token;

$key = random_bytes(32);

$token = Token::create(
    key: $key,
    data: [
        'foo' => 'bar',
    ]
);

try {
    $decode = Token::decode(
        key: $key,
        givenToken: $token
    );
} catch (TokenException) {
    echo 'Token invalid';
}

echo json_encode([
    'token' => $token,
    'payload' => $decode,
]);
