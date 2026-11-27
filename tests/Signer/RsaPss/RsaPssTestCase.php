<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\RsaPss;

use DateTimeImmutable;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\RsaPss;
use Lcobucci\JWT\Tests\Keys;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

use function assert;
use function chr;
use function file_get_contents;
use function hash;
use function is_string;
use function openssl_error_string;
use function openssl_public_decrypt;
use function ord;
use function pack;
use function PHPUnit\Framework\assertIsString;
use function PHPUnit\Framework\assertNotSame;
use function PHPUnit\Framework\assertSame;
use function strlen;
use function strpos;
use function substr;
use function trim;

use const OPENSSL_NO_PADDING;

abstract class RsaPssTestCase extends TestCase
{
    use Keys;

    abstract protected function algorithm(): RsaPss;

    abstract protected function algorithmId(): string;

    abstract protected function signatureAlgorithm(): string;

    abstract protected function getE2eTokenFilePath(): string;

    /** @return non-empty-string */
    private function getJwtContents(string $filename): string
    {
        $contents = file_get_contents($filename);
        assertIsString($contents);
        $tokenstring = trim($contents);
        assertNotSame('', $tokenstring);

        return $tokenstring;
    }

    private function getCurrentClock(): ClockInterface
    {
        return new class implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable();
            }
        };
    }

    #[PHPUnit\Test]
    final public function algorithmIdMustBeCorrect(): void
    {
        self::assertSame($this->algorithmId(), $this->algorithm()->algorithmId());
    }

    #[PHPUnit\Test]
    final public function signatureAlgorithmMustBeCorrect(): void
    {
        self::assertSame($this->signatureAlgorithm(), $this->algorithm()->algorithm());
    }

    #[PHPUnit\Test]
    public function signShouldReturnAValidOpensslSignature(): void
    {
        $payload   = 'testing';
        $signature = $this->algorithm()->sign($payload, self::$rsaKeys['private']);

        $publicKey = PublicKeyLoader::loadPublicKey(self::$rsaKeys['public']->contents());
        assert($publicKey instanceof RSA\PublicKey);

        self::assertTrue(
            $publicKey
                ->withHash($this->signatureAlgorithm())
                ->withMGFHash($this->signatureAlgorithm())
                ->verify($payload, $signature),
        );
    }

    #[PHPUnit\Test]
    public function signShouldReturnAValidOpensslSignatureWithPssKey(): void
    {
        $payload   = 'testing';
        $signature = $this->algorithm()->sign($payload, self::$rsaKeys['private_rsapss']);

        $publicKey = PublicKeyLoader::loadPublicKey(self::$rsaKeys['public_rsapss']->contents());
        assert($publicKey instanceof RSA\PublicKey);

        self::assertTrue(
            $publicKey
                ->withHash($this->signatureAlgorithm())
                ->withMGFHash($this->signatureAlgorithm())
                ->verify($payload, $signature),
        );
    }

    #[PHPUnit\Test]
    public function signShouldUseASaltAsLongAsTheHashOutput(): void
    {
        $signature = $this->algorithm()->sign('testing', self::$rsaKeys['private']);

        self::assertSame(strlen(hash($this->signatureAlgorithm(), '', true)), $this->saltLength($signature));
    }

    #[PHPUnit\Test]
    public function signShouldNotLeaveOpenSSLErrorsBehindWhenKeyIsNotParseable(): void
    {
        self::clearOpenSSLErrors();

        try {
            $this->algorithm()->sign('testing', InMemory::plainText('blablabla'));
        } catch (InvalidKeyProvided) {
        }

        self::assertFalse(openssl_error_string());
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason: Unable to read key');
        $this->expectExceptionCode(0);

        $this->algorithm()->sign('testing', InMemory::plainText('blablabla'));
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage(
            'The type of the provided key is not "RSA", "phpseclib3\Crypt\EC\PrivateKey" provided',
        );
        $this->expectExceptionCode(0);

        $this->algorithm()->sign('testing', self::$ecdsaKeys['private']);
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyLengthIsBelowMinimum(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 2048 bits, only 512 bits provided');
        $this->expectExceptionCode(0);

        $this->algorithm()->sign('testing', self::$rsaKeys['private_short']);
    }

    #[PHPUnit\Test]
    public function verifyShouldReturnTrueWhenSignatureIsValid(): void
    {
        $payload    = 'testing';
        $privateKey = PublicKeyLoader::loadPrivateKey(self::$rsaKeys['private']->contents());
        assert($privateKey instanceof RSA\PrivateKey);

        $signature = $privateKey
            ->withHash($this->signatureAlgorithm())
            ->withMGFHash($this->signatureAlgorithm())
            ->sign($payload);

        self::assertTrue($this->algorithm()->verify($signature, $payload, self::$rsaKeys['public']));
    }

    #[PHPUnit\Test]
    public function verifyShouldReturnTrueWhenSignatureIsValidWithPssKey(): void
    {
        $payload    = 'testing';
        $privateKey = PublicKeyLoader::loadPrivateKey(self::$rsaKeys['private_rsapss']->contents());
        assert($privateKey instanceof RSA\PrivateKey);

        $signature = $privateKey
            ->withHash($this->signatureAlgorithm())
            ->withMGFHash($this->signatureAlgorithm())
            ->sign($payload);

        self::assertTrue($this->algorithm()->verify($signature, $payload, self::$rsaKeys['public_rsapss']));
    }

    #[PHPUnit\Test]
    public function verifyShouldReturnFalseWhenSignatureIsInvalid(): void
    {
        $signature = $this->algorithm()->sign('testing', self::$rsaKeys['private']);

        self::assertFalse($this->algorithm()->verify($signature, 'tampered', self::$rsaKeys['public']));
        self::assertFalse($this->algorithm()->verify('not a signature', 'testing', self::$rsaKeys['public']));
    }

    #[PHPUnit\Test]
    public function verifyShouldNotLeaveOpenSSLErrorsBehindWhenSignatureIsInvalid(): void
    {
        self::clearOpenSSLErrors();

        $this->algorithm()->verify('not a signature', 'testing', self::$rsaKeys['public']);

        self::assertFalse(openssl_error_string());
    }

    #[PHPUnit\Test]
    public function verifyShouldNotLeaveOpenSSLErrorsBehindWhenKeyIsNotParseable(): void
    {
        self::clearOpenSSLErrors();

        try {
            $this->algorithm()->verify('testing', 'testing', InMemory::plainText('blablabla'));
        } catch (InvalidKeyProvided) {
        }

        self::assertFalse(openssl_error_string());
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason: Unable to read key');
        $this->expectExceptionCode(0);

        $this->algorithm()->verify('testing', 'testing', InMemory::plainText('blablabla'));
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage(
            'The type of the provided key is not "RSA", "phpseclib3\Crypt\EC\PublicKey" provided',
        );
        $this->expectExceptionCode(0);

        $this->algorithm()->verify('testing', 'testing', self::$ecdsaKeys['public1']);
    }

    #[PHPUnit\Test]
    public function validateExistingPsTokenWithPublicKey(): void
    {
        $signer      = $this->algorithm();
        $publicKey   = self::$rsaKeys['token1_public'];
        $tokenstring = $this->getJwtContents($this->getE2eTokenFilePath());

        $clock = $this->getCurrentClock();

        $facade = new JwtFacade();
        $token  = $facade->parse($tokenstring, new SignedWith($signer, $publicKey), new LooseValidAt($clock));
        assertSame($this->algorithmId(), $token->headers()->get('alg'));
        assertSame('bar', $token->claims()->get('foo'));
    }

    private static function clearOpenSSLErrors(): void
    {
        do {
            $message = openssl_error_string();
        } while ($message !== false);
    }

    /**
     * Recovers the salt length from a signature made with `tests/_keys/rsa/private.key`
     *
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-9.1.2
     */
    private function saltLength(string $signature): int
    {
        $encoded = '';
        openssl_public_decrypt($signature, $encoded, self::$rsaKeys['public']->contents(), OPENSSL_NO_PADDING);
        assert(is_string($encoded));

        $hashLength = strlen(hash($this->signatureAlgorithm(), '', true));
        $maskedDb   = substr($encoded, 0, -$hashLength - 1);
        $hash       = substr($encoded, -$hashLength - 1, $hashLength);

        $mask = '';

        for ($counter = 0; strlen($mask) < strlen($maskedDb); ++$counter) {
            $mask .= hash($this->signatureAlgorithm(), $hash . pack('N', $counter), true);
        }

        $db    = $maskedDb ^ substr($mask, 0, strlen($maskedDb));
        $db[0] = chr(ord($db[0]) & 0x7f);

        $separator = strpos($db, "\x01");
        assert($separator !== false);

        return strlen($db) - $separator - 1;
    }
}
