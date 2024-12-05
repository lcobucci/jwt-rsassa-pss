<?php
declare(strict_types=1);

namespace Lcobucci\JWTRsaPss\Signer\RsaPss;

use Lcobucci\JWTRsaPss\Signer\RsaPss;

final readonly class Sha256 extends RsaPss
{
    public function algorithmId(): string
    {
        return 'PS256';
    }

    public function algorithm(): string
    {
        return 'sha256';
    }
}
