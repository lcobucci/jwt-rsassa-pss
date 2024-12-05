<?php
declare(strict_types=1);

namespace Lcobucci\JWTRsaPss\Signer\RsaPss;

use Lcobucci\JWTRsaPss\Signer\RsaPss;

final readonly class Sha384 extends RsaPss
{
    public function algorithmId(): string
    {
        return 'PS384';
    }

    public function algorithm(): string
    {
        return 'sha384';
    }
}
