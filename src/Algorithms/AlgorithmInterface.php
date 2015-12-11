<?php

namespace Bendbennett\JWT\Algorithms;


/**
 * Interface AlgoInterface
 * @package Bendbennett\JWT\Providers
 */
interface AlgorithmInterface
{
    /**
     * @return mixed
     */
    public function getKeyForSigning();

    /**
     * @return mixed
     */
    public function getKeyForVerifying();
}