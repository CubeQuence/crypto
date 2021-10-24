<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\TokenException;
use CQ\Crypto\Models\TokenKey;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Protocol\Version4;

final class Token
{
    private TokenKey $key;

    public function __construct(string | null $key = null)
    {
        $this->setKey(key: $key);
    }

    public function setKey(string | null $key = null): void
    {
        $this->key = new TokenKey(encodedKey: $key);
    }

    public function exportKey(): string
    {
        return $this->key->export();
    }

    public function encrypt(array $data): string
    {
        return Version4::encrypt(
            data: json_encode($data),
            key: $this->key->getEncryption()
        );
    }

    public function decrypt(string $token): bool | object
    {
        try {
            $data = Version4::decrypt(
                data: $token,
                key: $this->key->getEncryption()
            );
        } catch (PasetoException) {
            throw new TokenException();
        }

        return json_decode($data);
    }

    public function sign(array $data): string
    {
        return Version4::sign(
            data: json_encode($data),
            key: $this->key->getAuthentication()
        );
    }

    public function verify(string $signedToken): string
    {
        return Version4::verify(
            signMsg: $signedToken,
            key: $this->key->getAuthentication()
        );
    }
}
