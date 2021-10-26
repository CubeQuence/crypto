<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\Exceptions\CryptoException;
use CQ\Crypto\File;

try {
    $orginalFile = 'test.txt';
    $encryptedFile = 'test.txt.enc';

    $file = new File(
        rootPath: __DIR__,
        // key: '', // If no key is provided a new one is generated
        keyType: 'symmetric',
    );

    $file2 = new File(
        rootPath: __DIR__,
        key: $file->exportKey(),
        keyType: 'symmetric',
    );

    $checksum = $file->checksum(path: $orginalFile);

    $encrypt = $file->encrypt(sourcePath: $orginalFile, destinationPath: $encryptedFile);
    $decrypt = $file2->decrypt(sourcePath: $encryptedFile, destinationPath: $orginalFile);

    // Symmetric file crypto doesn't support signing and verifying
} catch (CryptoException $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'orginalFile' => $orginalFile,
    'encryptedFile' => $encryptedFile,

    'key' => [
        'exportKey' => $file->exportKey(),
    ],

    'actions' => [
        'checksum' => $checksum,
        'encrypt' => $encrypt,
        'decrypt' => $decrypt,
    ],
]);
