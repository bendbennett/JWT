<?php

namespace Bendbennett\JWT\Validators;

interface PayloadValidatorInterface
{
    public function validateClaims(array $requiredClaims, array $defaultClaims, array $claims);
}