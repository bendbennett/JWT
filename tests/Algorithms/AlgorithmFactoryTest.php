<?php

namespace Bendbennett\JWT\Algorithms;

use phpmock\mockery\PHPMockery;

class AlgorithmFactoryTest extends \PHPUnit_Framework_TestCase
{
    public static $basePath;
    /**
     * @test
     * @expectedException \Exception
     * @group algorithmFactory
     */
    public function shouldThrowExceptionIfAlgorithmNotAllowed()
    {
        $algorithmFactory = new AlgorithmFactory(array('algorithm' => '', 'secret' => '', 'privateKey' => '', 'publicKey' => ''));
        $algorithmFactory->make();
    }

    /**
     * @test
     * @group algorithmFactory
     */
    public function shouldReturnSymmetricAlgorithm()
    {
        $algorithmFactory = new AlgorithmFactory(array('algorithm' => 'HS256', 'secret' => '', 'privateKey' => '', 'publicKey' => ''));
        $algorithm = $algorithmFactory->make();

        $this->assertInstanceOf('Bendbennett\JWT\algorithms\algorithmInterface', $algorithm);
        $this->assertInstanceOf('Bendbennett\JWT\algorithms\SymmetricAlgorithm', $algorithm);
    }

    /**
     * @test
     * @group algorithmFactory
     */
    public function shouldReturnAsymmetricAlgorithm()
    {
        PHPMockery::mock(__NAMESPACE__, "base_path")->andReturn('/some/directory/or/other');

        $algorithmFactory = new AlgorithmFactory(array('algorithm' => 'ES256', 'secret' => '', 'privateKey' => '', 'publicKey' => ''));
        $algorithm = $algorithmFactory->make();

        $this->assertInstanceOf('Bendbennett\JWT\Algorithms\algorithmInterface', $algorithm);
        $this->assertInstanceOf('Bendbennett\JWT\Algorithms\AsymmetricAlgorithm', $algorithm);
    }

}
