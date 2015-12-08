<?php

namespace Bendbennett\JWT\Algorithims;

use phpmock\mockery\PHPMockery;

class AlgorithimFactoryTest extends \PHPUnit_Framework_TestCase
{
    public static $basePath;
    /**
     * @test
     * @expectedException \Exception
     * @group algorithimFactory
     */
    public function shouldThrowExceptionIfAlgorithimNotAllowed()
    {
        $algorithimFactory = new AlgorithimFactory(array('algorithim' => '', 'secret' => '', 'privateKey' => '', 'publicKey' => ''));
        $algorithimFactory->make();
    }

    /**
     * @test
     * @group algorithimFactory
     */
    public function shouldReturnSymmetricAlgorithim()
    {
        $algorithimFactory = new AlgorithimFactory(array('algorithim' => 'HS256', 'secret' => '', 'privateKey' => '', 'publicKey' => ''));
        $algorithim = $algorithimFactory->make();

        $this->assertInstanceOf('Bendbennett\JWT\Algorithims\AlgorithimInterface', $algorithim);
        $this->assertInstanceOf('Bendbennett\JWT\Algorithims\SymmetricAlgorithim', $algorithim);
    }

    /**
     * @test
     * @group algorithimFactory
     */
    public function shouldReturnAsymmetricAlgorithim()
    {
        PHPMockery::mock(__NAMESPACE__, "base_path")->andReturn('/some/directory/or/other');

        $algorithimFactory = new AlgorithimFactory(array('algorithim' => 'ES256', 'secret' => '', 'privateKey' => '', 'publicKey' => ''));
        $algorithim = $algorithimFactory->make();

        $this->assertInstanceOf('Bendbennett\JWT\Algorithims\AlgorithimInterface', $algorithim);
        $this->assertInstanceOf('Bendbennett\JWT\Algorithims\AsymmetricAlgorithim', $algorithim);
    }

}
