<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\Asymmetric;

try {
    $string = 'Hello World!';

    $asymmetric = new Asymmetric(); // If no key is provided a new one is generated
    $asymmetric2 = new Asymmetric(key: $asymmetric->exportPublicKey()); // Instance with only public key

    /**
     * There are two different ways to export AssymetricKey's
     *
     * The first is using the exportKey() method, this returns the full key
     * If you import this key you can execute all functions
     *
     * The second is using the exportPublicKey() method, this only returns the public key
     * If you import this key you can't execute decrypt() or sign()
     *
     * $exportFullKey = $asymmetric->exportKey();
     * $exportPublicKey = $asymmetric->exportPublicKey();
     */

    $encrypt = $asymmetric2->encrypt(plaintext: $string); // Using public key
    $decrypt = $asymmetric->decrypt(ciphertext: $encrypt); // Using private key

    $sign = $asymmetric->sign(plaintext: $string); // Using private key
    $verify = $asymmetric2->verify(plaintext: $string, signature: $sign); // Using public key
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,

    'key' => [
        'exportKey' => $asymmetric->exportKey(),
        'exportPublicKey' => $asymmetric->exportPublicKey(),
    ],

    'actions' => [
        'encrypt' => $encrypt,
        'decrypt' => $decrypt,
        'sign' => $sign,
        'verify' => $verify,
    ],
]);
