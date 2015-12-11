<?php

namespace Bendbennett\JWT\Algorithms;

class SymmetricAlgorithm implements AlgorithmInterface
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