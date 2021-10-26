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
        keyType: 'asymmetric',
    );

    $file2 = new File(
        rootPath: __DIR__,
        key: $file->exportPublicKey(),
        keyType: 'asymmetric',
    );

    $checksum = $file->checksum(path: $orginalFile);

    $encrypt = $file2->encrypt(sourcePath: $orginalFile, destinationPath: $encryptedFile);
    $decrypt = $file->decrypt(sourcePath: $encryptedFile, destinationPath: $orginalFile);

    $sign = $file->sign(path: $orginalFile);
    $verify = $file2->verify(path: $orginalFile, signature: $sign);
} catch (CryptoException $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'orginalFile' => $orginalFile,
    'encryptedFile' => $encryptedFile,

    'key' => [
        'exportKey' => $file->exportKey(),
        'exportPublicKey' => $file->exportPublicKey(),
    ],

    'actions' => [
        'checksum' => $checksum,
        'encrypt' => $encrypt,
        'decrypt' => $decrypt,
        'sign' => $sign,
        'verify' => $verify
    ],
]);
