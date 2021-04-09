<?php

declare(strict_types=1);

use CQ\Crypto\Asymmetric;
use CQ\Crypto\Models\AsymmetricKey;

try {
    $string = 'Hello World!';

    // If no encodedKey is provided a new one is generated
    $keypair = new AsymmetricKey();

    /**
     * There are two different ways to export AssymetricKey's
     *
     * The first is using the export() method, this returns the private encodedKey
     * If you import this key you can execute all functions
     *
     * The second is using the exportPublic() method, this returns the public encodedKey
     * If you import this key you can't execute decrypt() or sign()
     */
    $exportKeypair = $keypair->export();
    $exportPublicKeypair = $keypair->exportPublic();

    // By providing an encodedKey you can import and use it
    $keypair2 = new AsymmetricKey(encodedKey: $exportPublicKeypair);

    $client = new Asymmetric(keypair: $keypair);
    $client2 = new Asymmetric(keypair: $keypair2);

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
    'export' => $exportKeypair,
    'exportPublic' => $exportPublicKeypair,
    'encrypted' => $encryptedString,
    'decrypted' => $decryptedString,
    'signature' => $signature,
    'verify' => $verify,
]);
