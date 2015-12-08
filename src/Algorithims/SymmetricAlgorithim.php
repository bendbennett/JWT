<?php

namespace Bendbennett\JWT\Algorithims;

class SymmetricAlgorithim implements AlgorithimInterface
{
    protected $secret;

    public function __construct($secret)
    {
        $this->secret = $secret;
    }

    public function getKeyForSigning()
    {
        return $this->secret;
    }

    public function getKeyForVerifying()
    {
        return $this->secret;
    }
}