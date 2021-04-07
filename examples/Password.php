<?php

declare(strict_types=1);

use CQ\Crypto\Password;
use CQ\Crypto\Symmetric;

try {
    $encryptionKey = Symmetric::genKey();
    $context = null; // Optional variable

    $password = new Password(
        keystring: $encryptionKey
    );

    $plaintextPassword = 'Hello World!';
    $encryptedHashedPassword = $password->hash(
        plaintextPassword: $plaintextPassword,
        context: $context
    );
    $passwordVerify = $password->verify(
        plaintextPassword: $plaintextPassword,
        encryptedHashedPassword: $encryptedHashedPassword,
        context: $context
    );
} catch (\Throwable $th) {
    echo $th->getMessage();
    exit;
}

echo json_encode([
    'plaintextPassword' => $plaintextPassword,
    'hashedPassword' => $encryptedHashedPassword,
    'verifyPassword' => $passwordVerify,
]);
