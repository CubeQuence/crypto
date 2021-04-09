<?php

declare(strict_types=1);

use CQ\Crypto\Asymmetric;
use CQ\Crypto\Models\AsymmetricKey;

try {
    $string = 'Hello World!';

    // If no encodedKey is provided a new one is generated
    $keyInstance = new AsymmetricKey();

    /**
     * There are two different ways to export AssymetricKey's
     *
     * The first is using the export() method, this returns the full key
     * If you import this key you can execute all functions
     *
     * The second is using the exportPublic() method, this only returns the public key
     * If you import this key you can't execute decrypt() or sign()
     */
    $exportFullKey = $keyInstance->export();
    $exportPublicKey = $keyInstance->exportPublic();

    // By providing an encodedKey you can import and use it
    $keyInstance2 = new AsymmetricKey(encodedKey: $exportPublicKey);

    $client = new Asymmetric(key: $keyInstance);
    $client2 = new Asymmetric(key: $keyInstance2);

    $encryptedString = $client2->encrypt( // Encrypt using public key
        string: $string
    );
    $decryptedString = $client->decrypt(
        encryptedString: $encryptedString
    );

    $signature = $client->sign(
        string: $string
    );
    $verify = $client2->verify( // Verify using public key
        string: $string,
        signature: $signature
    );
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'exportFullKey' => $exportFullKey,
    'exportPublicKey' => $exportPublicKey,
    'encryptedString' => $encryptedString,
    'decrypted' => $decryptedString,
    'signature' => $signature,
    'verify' => $verify,
]);
