<?php

declare(strict_types=1);

use CQ\Crypto\Models\SymmetricKey;
use CQ\Crypto\Symmetric;

try {
    $string = 'Hello World!';

    // If no encodedKey is provided a new one is generated
    $key = new SymmetricKey();
    $exportKey = $key->export();

    // By providing an exported key you can import it
    $key2 = new SymmetricKey(encodedKey: $exportKey);
    $exportKey2 = $key2->export();

    $client = new Symmetric(
        key: $key
    );
    $client2 = new Symmetric(
        key: $key2
    );

    $encryptedString = $client->encrypt(
        string: $string
    );
    $decryptedString = $client2->decrypt(
        encryptedString: $encryptedString
    );

    $signature = $client->sign(
        string: $string
    );
    $verify = $client2->verify(
        string: $string,
        signature: $signature
    );
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'export' => $exportKey,
    'export2' => $exportKey2,
    'encrypted' => $encryptedString,
    'decrypted' => $decryptedString,
    'signature' => $signature,
    'verify' => $verify,
]);
