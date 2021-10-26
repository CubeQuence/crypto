<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\File;
use CQ\Crypto\Models\AsymmetricKey;

try {
    $orginalFile = 'test.txt';
    $encryptedFile = 'test.txt.enc';

    $asymmetricKey = new AsymmetricKey();

    // Public only key can still be used for encryption and verifying signatures
    $asymmetricKey2 = new AsymmetricKey(encodedKey: $asymmetricKey->exportPublic());

    $file = new File(
        rootPath: __DIR__
    );

    $checksum = $file->checksum(
        path: $orginalFile
    );

    $file->encrypt(
        sourcePath: $orginalFile,
        destinationPath: $encryptedFile,
        key: $asymmetricKey2
    );

    $file->decrypt(
        sourcePath: $encryptedFile,
        destinationPath: $orginalFile,
        key: $asymmetricKey
    );

    $signature = $file->sign(
        path: $orginalFile,
        key: $asymmetricKey
    );

    $verify = $file->verify(
        path: $orginalFile,
        signature: $signature,
        key: $asymmetricKey2
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
