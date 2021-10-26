<?php

declare(strict_types=1);

namespace CQ\Crypto;

use CQ\Crypto\Exceptions\CryptoException;
use CQ\Crypto\Exceptions\KeyException;
use CQ\Crypto\Models\AsymmetricKey;
use CQ\Crypto\Models\SymmetricKey;
use ParagonIE\Halite\File as HaliteFile;

final class File
{
    private AsymmetricKey | SymmetricKey $key;

    public function __construct(
        private string $rootPath,
        string $key = '',
        string $keyType = 'symmetric'
    ) {
        if (!str_ends_with(haystack: $this->rootPath, needle: '/')) {
            $this->rootPath .= '/';
        }

        $this->setKey(key: $key, keyType: $keyType);
    }

    public function setKey(
        string $key,
        string $keyType = 'symmetric'
    ): void {
        $this->key = match ($keyType) {
            'symmetric' => new SymmetricKey(encodedKey: $key),
            'asymmetric' => new AsymmetricKey(encodedKey: $key),
            default => throw new KeyException(message: 'Invalid keyType, use symmetric or asymmetric')
        };
    }

    public function exportKey(): string
    {
        return $this->key->export();
    }

    // Only works if assymetric keys are used
    public function exportPublicKey(): string
    {
        return $this->key->exportPublic();
    }

    /**
     * Get checksum of file
     */
    public function checksum(string $path): string
    {
        try {
            return HaliteFile::checksum(filePath: $this->rootPath . $path);
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    /**
     * Encrypt file using either Symmetric or Assymetric keys,
     * return number of bytes written
     */
    public function encrypt(string $sourcePath, string $destinationPath): int
    {
        try {
            if ($this->key instanceof AsymmetricKey) {
                return HaliteFile::seal(
                    input: $sourcePath,
                    output: $destinationPath,
                    publicKey: $this->key->getEncryption()->getPublicKey()
                );
            }

            return HaliteFile::encrypt(
                input: $sourcePath,
                output: $destinationPath,
                key: $this->key->getEncryption()
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    /**
     * Decrypt file using either Symmetric or Assymetric keys
     */
    public function decrypt(string $sourcePath, string $destinationPath): bool
    {
        try {
            if ($this->key instanceof AsymmetricKey) {
                return HaliteFile::unseal(
                    input: $sourcePath,
                    output: $destinationPath,
                    secretKey: $this->key->getEncryption()->getSecretKey()
                );
            }

            return HaliteFile::decrypt(
                input: $sourcePath,
                output: $destinationPath,
                key: $this->key->getEncryption()
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    /**
     * Sign file using an assymetric key
     */
    public function sign(string $path): string
    {
        try {
            return HaliteFile::sign(
                filename: $path,
                secretKey: $this->key->getAuthentication()->getSecretKey()
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }

    /**
     * Verify file using a signature and an assymetric key
     */
    public function verify(string $path, string $signature): bool
    {
        try {
            return HaliteFile::verify(
                filename: $path,
                publicKey: $this->key->getAuthentication()->getPublicKey(),
                signature: $signature
            );
        } catch (\Throwable $th) {
            throw new CryptoException(message: $th->getMessage());
        }
    }
}
