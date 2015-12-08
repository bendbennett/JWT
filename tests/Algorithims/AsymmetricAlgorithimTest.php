<?php

use Bendbennett\JWT\Algorithims\AsymmetricAlgorithim;

class AsymmetricAlgorithimTest extends PHPUnit_Framework_TestCase
{

    /** @var  \Bendbennett\JWT\Algorithims\AsymmetricAlgorithim */
    protected $asymmetricAlgorithim;


    public function setUp()
    {
        $this->asymmetricAlgorithim = new AsymmetricAlgorithim('', '', '');
    }

    /**
     * @test
     * @expectedException \Exception
     */
    public function getKeyForSigning_should_throw_exception_when_no_private_key_found()
    {
        $this->asymmetricAlgorithim->getKeyForSigning();
    }

    /**
     * @test
     * @expectedException \Exception
     */
    public function getKeyForVerifying_should_throw_exception_when_no_public_key_found()
    {
        $this->asymmetricAlgorithim->getKeyForVerifying();
    }
}
