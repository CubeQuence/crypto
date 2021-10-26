<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\File;
use CQ\Crypto\Models\SymmetricKey;

try {
    $orginalFile = 'test.txt';
    $encryptedFile = 'test.txt.enc';

    $symmetricKey = new SymmetricKey();
    $symmetricKey2 = new SymmetricKey(encodedKey: $symmetricKey->export());

    $file = new File(
        rootPath: __DIR__
    );

    $checksum = $file->checksum(
        path: $orginalFile
    );

    $file->encrypt(
        sourcePath: $orginalFile,
        destinationPath: $encryptedFile,
        key: $symmetricKey
    );

    $file->decrypt(
        sourcePath: $encryptedFile,
        destinationPath: $orginalFile,
        key: $symmetricKey2
    );

    // Symmetric file crypto doesn't support signing and verifying
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'checksum' => $checksum,
]);
