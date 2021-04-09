<?php

declare(strict_types=1);

use CQ\Crypto\File;
use CQ\Crypto\Models\AsymmetricKey;
use CQ\Crypto\Models\SymmetricKey;

try {
    // To try this please create a file named test.txt
    // Otherwise this code will fail

    $sourcePath = 'test.txt';
    $symmetricKey = new SymmetricKey();
    $asymmetricKey = new AsymmetricKey();

    $cryptoFileHandler = new File(
        rootPath: __DIR__
    );

    $checksum = $cryptoFileHandler->checksum(
        path: $sourcePath
    );

    $cryptoFileHandler->encrypt(
        sourcePath: $sourcePath,
        destinationPath: 'test.txt.enc',
        key: $symmetricKey // Also accepts $asymmetricKey
    );

    $cryptoFileHandler->decrypt(
        sourcePath: 'test.txt.enc',
        destinationPath: $sourcePath,
        key: $symmetricKey // Also accepts $asymmetricKey
    );

    $signature = $cryptoFileHandler->sign(
        path: $sourcePath,
        key: $asymmetricKey
    );

    $verify = $cryptoFileHandler->verify(
        path: $sourcePath,
        signature: $signature,
        key: $asymmetricKey
    );
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'checksum' => $checksum,
    'signature' => $signature,
    'verify' => $verify,
]);
