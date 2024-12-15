<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\RsaPss;

use Lcobucci\JWT\Signer\RsaPss;

final readonly class Sha512 extends RsaPss
{
    public function algorithmId(): string
    {
        return 'PS512';
    }

    public function algorithm(): string
    {
        return 'sha512';
    }
}
