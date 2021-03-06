<?php

namespace Bendbennett\JWT;

use Namshi\JOSE\SimpleJWS;

class JWSProxy extends SimpleJWS
{
    /**
     * Proxy JWS::load static method to allow unit testing.
     * Creates an instance of a JWS from a JWT.
     *
     * @param string $jwsTokenString
     * @return JWS
     * @throws \InvalidArgumentException
     */
    public function callLoad($jwsTokenString, $allowUnsecure = false, Encoder $encoder = null, $encryptionEngine = 'OpenSSL')
    {
        return parent::load($jwsTokenString, $allowUnsecure, $encoder, $encryptionEngine); // TODO: Change the autogenerated stub
    }
}