<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\CryptoException;
use CQ\Crypto\Models\TokenKey;
use CQ\Crypto\Providers\CryptoProvider;
use ParagonIE\Paseto\Protocol\Version4;

final class Token extends CryptoProvider
{
    private TokenKey $key;

    public function setKey(string $key): void
    {
        $this->key = new TokenKey(encodedKey: $key);
    }

    public function exportKey(): string
    {
        return $this->key->export();
    }

    public function encrypt(array $data): string
    {
        try {
            return Version4::encrypt(
                data: json_encode($data),
                key: $this->key->getEncryption()
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    public function decrypt(string $token): bool | object
    {
        try {
            $data = Version4::decrypt(
                data: $token,
                key: $this->key->getEncryption()
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }

        return json_decode($data);
    }
}
