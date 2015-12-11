<?php

use Bendbennett\JWT\Algorithms\SymmetricAlgorithm;

class SymmetricAlgorithmTest extends PHPUnit_Framework_TestCase
{

    /** @var Bendbennett\JWT\Algorithms\SymmetricAlgorithm */
    public $symAlgo;


    public function setUp()
    {
        $this->symAlgo = new SymmetricAlgorithm('secret');
    }


    /** @test */
    public function getKeyForSigning_should_return_secret()
    {
        $this->assertEquals('secret', $this->symAlgo->getKeyForSigning());
    }


    /** @test */
    public function getKeyForVerifying_should_return_secret()
    {
        $this->assertEquals('secret', $this->symAlgo->getKeyForVerifying());
    }


}
