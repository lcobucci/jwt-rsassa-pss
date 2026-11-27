<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;
use OpenSSLAsymmetricKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\Exception\NoKeyLoadedException;

use function assert;
use function extension_loaded;
use function is_array;
use function is_int;
use function is_string;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

use const OPENSSL_KEYTYPE_RSA;
use const OPENSSL_PKCS1_PSS_PADDING;
use const OPENSSL_VERSION_NUMBER;
use const PHP_EOL;
use const PHP_VERSION_ID;

abstract readonly class RsaPss implements Signer
{
    private const int MINIMUM_KEY_LENGTH = 2048;

    final public function sign(string $payload, Key $key): string
    {
        // Both paths give the same results, so the tests cannot tell which one ran
        /** @infection-ignore-all */
        if (! self::supportsNativeSignatures()) {
            return $this->signWithPhpseclib($payload, $key);
        }

        $private = self::nativeRsaKey(openssl_pkey_get_private($key->contents(), $key->passphrase()));

        if ($private === null) {
            return $this->signWithPhpseclib($payload, $key);
        }

        $details = openssl_pkey_get_details($private);

        /** @infection-ignore-all */
        assert(is_array($details) && is_int($details['bits']));

        if ($details['bits'] < self::MINIMUM_KEY_LENGTH) {
            throw InvalidKeyProvided::tooShort(self::MINIMUM_KEY_LENGTH, $details['bits']);
        }

        $signature = '';

        if (! openssl_sign($payload, $signature, $private, $this->algorithm(), OPENSSL_PKCS1_PSS_PADDING)) {
            /** @infection-ignore-all */
            throw CannotSignPayload::errorHappened(self::openSSLErrors());
        }

        /** @infection-ignore-all */
        assert(is_string($signature) && $signature !== '');

        return $signature;
    }

    final public function verify(string $expected, string $payload, Key $key): bool
    {
        // Both paths give the same results, so the tests cannot tell which one ran
        /** @infection-ignore-all */
        if (! self::supportsNativeSignatures()) {
            return $this->verifyWithPhpseclib($expected, $payload, $key);
        }

        $public = self::nativeRsaKey(openssl_pkey_get_public($key->contents()));

        if ($public === null) {
            return $this->verifyWithPhpseclib($expected, $payload, $key);
        }

        $result = openssl_verify($payload, $expected, $public, $this->algorithm(), OPENSSL_PKCS1_PSS_PADDING);
        self::clearOpenSSLErrors();

        return $result === 1;
    }

    /**
     * PHP 8.5 lets ext-openssl apply the PSS padding, and OpenSSL 3.1+ then defaults the salt length to the
     * digest length, as RFC 7518 requires (older versions use the maximum length).
     *
     * @infection-ignore-all
     */
    private static function supportsNativeSignatures(): bool
    {
        return PHP_VERSION_ID >= 80500
            && extension_loaded('openssl')
            && OPENSSL_VERSION_NUMBER >= 0x30100000;
    }

    /**
     * Returns null when ext-openssl cannot use the key, to let phpseclib handle it (and report the errors)
     *
     * Keys restricted to RSASSA-PSS are left to phpseclib too: ext-openssl does not accept a padding for them.
     */
    private static function nativeRsaKey(OpenSSLAsymmetricKey|false $key): ?OpenSSLAsymmetricKey
    {
        if ($key === false) {
            self::clearOpenSSLErrors();

            return null;
        }

        $details = openssl_pkey_get_details($key);
        assert(is_array($details));

        return $details['type'] === OPENSSL_KEYTYPE_RSA ? $key : null;
    }

    private static function clearOpenSSLErrors(): void
    {
        do {
            $message = openssl_error_string();
        } while ($message !== false);
    }

    /** @infection-ignore-all */
    private static function openSSLErrors(): string
    {
        $errors = '';

        while (($message = openssl_error_string()) !== false) {
            $errors .= PHP_EOL . '* ' . $message;
        }

        return $errors;
    }

    /** @return non-empty-string */
    private function signWithPhpseclib(string $payload, Key $key): string
    {
        try {
            $private = PublicKeyLoader::loadPrivateKey($key->contents(), $key->passphrase());
        } catch (NoKeyLoadedException $e) {
            throw new InvalidKeyProvided('It was not possible to parse your key, reason: ' . $e->getMessage(), 0, $e);
        }

        if (! $private instanceof PrivateKey) {
            throw InvalidKeyProvided::incompatibleKeyType('RSA', $private::class);
        }

        if ($private->getLength() < self::MINIMUM_KEY_LENGTH) {
            throw InvalidKeyProvided::tooShort(self::MINIMUM_KEY_LENGTH, $private->getLength());
        }

        $signature = $private
            ->withPadding(RSA::SIGNATURE_PSS)
            ->withHash($this->algorithm())
            ->withMGFHash($this->algorithm())
            ->sign($payload);

        /** @infection-ignore-all */
        assert(is_string($signature) && $signature !== '');

        return $signature;
    }

    private function verifyWithPhpseclib(string $expected, string $payload, Key $key): bool
    {
        try {
            $public = PublicKeyLoader::loadPublicKey($key->contents());
        } catch (NoKeyLoadedException $e) {
            throw new InvalidKeyProvided('It was not possible to parse your key, reason: ' . $e->getMessage(), 0, $e);
        }

        if (! $public instanceof PublicKey) {
            throw InvalidKeyProvided::incompatibleKeyType('RSA', $public::class);
        }

        return $public
            ->withPadding(RSA::SIGNATURE_PSS)
            ->withHash($this->algorithm())
            ->withMGFHash($this->algorithm())
            ->verify($payload, $expected);
    }

    /**
     * Returns which algorithm to be used to create/verify the signature (using phpseclib hash identifiers)
     *
     * @internal
     */
    abstract public function algorithm(): string;
}
