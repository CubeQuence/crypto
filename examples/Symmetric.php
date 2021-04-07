<?php

declare(strict_types=1);

use CQ\Crypto\Symmetric;

try {
    $string = 'Hello World!';

    $symmetricKey = Symmetric::genKey();
    $symmetricClient = new Symmetric(
        keystring: $symmetricKey
    );
    $symmetricEncryptedString = $symmetricClient->encrypt(
        string: $string
    );
    $symmetricDecryptedString = $symmetricClient->decrypt(
        encryptedString: $symmetricEncryptedString
    );
    $symmetricSignature = $symmetricClient->sign(
        string: $string
    );
    $symmetricVerify = $symmetricClient->verify(
        string: $string,
        signature: $symmetricSignature
    );
} catch (\Throwable $th) {
    echo $th->getMessage();
    exit;
}

echo json_encode([
    'string' => $string,
    'symmetric' => [
        'key' => $symmetricKey,
        'encrypted' => $symmetricEncryptedString,
        'decrypted' => $symmetricDecryptedString,
        'signature' => $symmetricSignature,
        'verify' => $symmetricVerify,
    ],
]);
