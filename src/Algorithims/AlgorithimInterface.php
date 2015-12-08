<?php

namespace Bendbennett\JWT\Algorithims;


/**
 * Interface AlgoInterface
 * @package Bendbennett\JWT\Providers
 */
interface AlgorithimInterface
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