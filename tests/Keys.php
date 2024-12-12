<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Signer\Key;
use PHPUnit\Framework\Attributes as PHPUnit;

trait Keys
{
    /** @var array<string, Key> */
    protected static array $rsaKeys;

    /** @var array<string, Key> */
    protected static array $ecdsaKeys;

    #[PHPUnit\BeforeClass]
    public static function createRsaKeys(): void
    {
        if (isset(static::$rsaKeys)) {
            return;
        }

        static::$rsaKeys = [
            'private'           => Key\InMemory::file(__DIR__ . '/_keys/rsa/private.key'),
            'public'            => Key\InMemory::file(__DIR__ . '/_keys/rsa/public.key'),
            'private_short'     => Key\InMemory::file(__DIR__ . '/_keys/rsa/private_512.key'),
            'public_short'      => Key\InMemory::file(__DIR__ . '/_keys/rsa/public_512.key'),
            // The RSAPSS keys contain special configuration flags to indicate they are to be used with PSS
            'private_rsapss'    => Key\InMemory::file(__DIR__ . '/_keys/rsa/private_pss.key'),
            'public_rsapss'     => Key\InMemory::file(__DIR__ . '/_keys/rsa/public_pss.key'),
            'token1_public'     => Key\InMemory::file(__DIR__ . '/_tokens/token1.public.key'),
        ];
    }

    #[PHPUnit\BeforeClass]
    public static function createEcdsaKeys(): void
    {
        if (isset(static::$ecdsaKeys)) {
            return;
        }

        static::$ecdsaKeys = [
            'private'        => Key\InMemory::file(__DIR__ . '/_keys/ecdsa/private.key'),
            'public1'        => Key\InMemory::file(__DIR__ . '/_keys/ecdsa/public1.key'),
        ];
    }
}
