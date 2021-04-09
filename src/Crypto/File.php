<?php

declare(strict_types=1);

namespace CQ\Crypto;

use ParagonIE\Halite\File as FileCrypto;
use CQ\Crypto\Models\SymmetricKey;
use CQ\Crypto\Models\AsymmetricKey;

final class File
{
    public function __construct(
        private string $rootPath
    ) {
        if (!str_ends_with(
            haystack: $this->rootPath,
            needle: '/'
        )) {
            $this->rootPath = $this->rootPath . '/';
        }
    }

    /**
     * Get checksum of file,
     * optional keyed checksum
     */
    public function checksum(
        string $path,
        AsymmetricKey | SymmetricKey | null $key = null
    ): string {
        if ($key instanceof AsymmetricKey) {
            $key = $key->getAuthentication()->getPublicKey();
        }

        if ($key instanceof SymmetricKey) {
            $key = $key->getAuthentication();
        }

        return FileCrypto::checksum(
            filePath: $this->rootPath . $path,
            key: $key
        );
    }

    /**
     * Encrypt file using eithor Symmetric or Assymetric keys
     */
    public function encrypt(
        string $sourcePath,
        string $destinationPath,
        AsymmetricKey | SymmetricKey $key
    ): int {
        if ($key instanceof AsymmetricKey) {
            $key = $key->getEncryption()->getPublicKey();

            return FileCrypto::seal(
                input: $sourcePath,
                output: $destinationPath,
                publicKey: $key
            );
        }

        $key = $key->getEncryption();

        return FileCrypto::encrypt(
            input: $sourcePath,
            output: $destinationPath,
            key: $key
        );
    }

    /**
     * Decrypt file using eithor Symmetric or Assymetric keys
     */
    public function decrypt(
        string $sourcePath,
        string $destinationPath,
        AsymmetricKey | SymmetricKey $key
    ): bool {
        if ($key instanceof AsymmetricKey) {
            $key = $key->getEncryption()->getSecretKey();

            return FileCrypto::unseal(
                input: $sourcePath,
                output: $destinationPath,
                secretKey: $key
            );
        }

        $key = $key->getEncryption();

        return FileCrypto::decrypt(
            input: $sourcePath,
            output: $destinationPath,
            key: $key
        );
    }

    /**
     * Sign file using an assymetric key
     */
    public function sign(
        string $path,
        AsymmetricKey $key
    ): string {
        $key = $key->getAuthentication()->getSecretKey();

        return FileCrypto::sign(
            filename: $path,
            secretKey: $key
        );
    }

    /**
     * Verify file using a signature and an assymetric key
     */
    public function verify(
        string $path,
        string $signature,
        AsymmetricKey $key
    ): bool {
        $key = $key->getAuthentication()->getPublicKey();

        return FileCrypto::verify(
            filename: $path,
            publicKey: $key,
            signature: $signature
        );
    }
}
