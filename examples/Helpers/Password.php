<?php

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

use CQ\Crypto\Helpers\Password;

try {
    $string = 'verysecretpassword';

    $key = Password::generateKey();

    $hash = Password::hash(key: $key, plaintext: $string);
    $verify = Password::verify(
        key: $key,
        plaintext: $string,
        encryptedHash: $hash
    );
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,

    'key' => $key,

    'actions' => [
        'hash' => $hash,
        'verify' => $verify,
    ],
]);
