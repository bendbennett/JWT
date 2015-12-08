<?php


namespace Bendbennett\JWT;

interface PayloadInterface
{
    public function getClaim($key);

    public function getClaims();

    public function setClaim($key, $value);

    public function setClaims(array $claims);

    public function getPayload();
}