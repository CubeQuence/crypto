<?php

declare(strict_types=1);

use CQ\Crypto\Models\SymmetricKey;
use CQ\Crypto\Password;

try {
    $string = 'Hello World!';
    $context = null;

    $key = new SymmetricKey();
    $password = new Password(key: $key);

    $encryptedHashedPassword = $password->hash(
        plaintextPassword: $string,
        context: $context
    );
    $verify = $password->verify(
        plaintextPassword: $string,
        encryptedHashedPassword: $encryptedHashedPassword,
        context: $context
    );
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'context' => $context,
    'encryptedHashedPassword' => $encryptedHashedPassword,
    'verify' => $verify,
]);
