<?php

use Bendbennett\JWT\Algorithims\SymmetricAlgorithim;

class SymmetricAlgoTest extends PHPUnit_Framework_TestCase
{

    /** @var Bendbennett\JWT\Algorithims\SymmetricAlgorithim */
    public $symAlgo;


    public function setUp()
    {
        $this->symAlgo = new SymmetricAlgorithim('secret');
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
