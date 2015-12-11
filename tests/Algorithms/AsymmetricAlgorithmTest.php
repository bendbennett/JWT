<?php

use Bendbennett\JWT\Algorithms\AsymmetricAlgorithm;

class AsymmetricAlgorithmTest extends PHPUnit_Framework_TestCase
{

    /** @var  \Bendbennett\JWT\Algorithms\AsymmetricAlgorithm */
    protected $asymmetricAlgorithm;


    public function setUp()
    {
        $this->asymmetricAlgorithm = new AsymmetricAlgorithm('', '', '');
    }

    /**
     * @test
     * @expectedException \Exception
     */
    public function getKeyForSigning_should_throw_exception_when_no_private_key_found()
    {
        $this->asymmetricAlgorithm->getKeyForSigning();
    }

    /**
     * @test
     * @expectedException \Exception
     */
    public function getKeyForVerifying_should_throw_exception_when_no_public_key_found()
    {
        $this->asymmetricAlgorithm->getKeyForVerifying();
    }
}
