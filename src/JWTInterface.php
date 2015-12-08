<?php


namespace Bendbennett\JWT;

interface JWTInterface {

    public function create(array $payload);
}