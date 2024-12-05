# jwt-rsapss
Implements JWT PS256/384/512 algorithm for lcobucci/jwt

## Motivation

The JWT algorithms PS256, PS384 and PS512 are using a modified padding mechanism that uses randomness and creates different tokens each time.

The RSASSA-PSS (probabilistic signature scheme[1]) padding algorithm suggests it's security is mathematically proven to relate to the RSA problem[2].

However, this statement alone should not influence your judgement when asked to choose a signature algorithm for a JWT that you create.
Consider using an elliptic curve signature instead.
If however you are required to consume a token signed with a PS algorithm, you have no choice.

[1]: https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
[2]: https://en.wikipedia.org/wiki/RSA_problem

## Implementation details

This library offloads the entire handling of cryptographic operations onto phpseclib/phpseclib V3, which is added as a dependency.
This dependency utilizes some PHP extensions that will speed up execution times, and fall back to native PHP implementations otherwise:

- ext-gmp should be favoured as it greatly speeds up everything.
- ext-openssl would be the alternative extension that does the heavy crypto lifting with decent performance.
- ext-bcmath can improve performance in some situations, but not all.

PhpSecLib offers some benchmark figures[3] - please verify your own performance numbers in case speed is a concern.

[3]: https://phpseclib.com/docs/speed

This library component is intentionally not part of lcobucci/jwt because it would force every user to install this dependency, with marginal benefit, as the PS signatures are rare.

## Usage

In order to install this package, all you'd need is

`composer require lcobucci/jwt-rsassa-pss`

For a complete dependency tree, it is recommended to also include

`composer require lcobucci/jwt`

as the code here makes use of the main library, and you will also utilize it's code directly, i.e. using validators, builders, interfaces.

