<?php

namespace Bendbennett\JWT\Utilities;

interface PayloadUtilitiesInterface
{
    public function getIat();

    public function getExp();

    public function getNbf();
}