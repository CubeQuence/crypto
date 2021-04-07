<?php

declare(strict_types=1);

use CQ\Crypto\Hash;

try {
    $string = 'Hello World!';

    $hash = Hash::make(
        string: $string
    );
    $verify = Hash::verify(
        string: $string,
        hash: $hash
    );
} catch (\Throwable $th) {
    echo $th->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'hash' => $hash,
    'verify' => $verify,
]);
