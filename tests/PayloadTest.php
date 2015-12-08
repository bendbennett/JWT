<?php

namespace Bendbennett\JWT;

use phpmock\mockery\PHPMockery;

class PayloadTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Mockery\MockInterface
     */
    protected $request;

    /**
     * @var \Mockery\MockInterface
     */
    protected $payloadUtilities;

    /**
     * @var \Mockery\MockInterface
     */
    protected $payloadValidator;


    public function setUp()
    {
        PHPMockery::mock(__NAMESPACE__, "uniqid")->withAnyArgs()->andReturn('a1b2c3d4');

        $this->request = \Mockery::mock('Illuminate\Http\Request');
        $this->request->shouldReceive('url')->once()->andReturn('http://some.url.com');

        $this->payloadUtilities = \Mockery::mock('Bendbennett\JWT\Utilities\PayloadUtilities');
        $this->payloadUtilities->shouldReceive('getIat')->once()->andReturn(1);
        $this->payloadUtilities->shouldReceive('getExp')->once()->andReturn(3601);
        $this->payloadUtilities->shouldReceive('getNbf')->once()->andReturn(1);

        $this->payloadValidator = \Mockery::mock('Bendbennett\JWT\Validators\PayloadValidator');
    }

    public function tearDown()
    {
        \Mockery::close();
    }

    /** @test
     * @group payload
     */
    public function callingConstructorShouldSetDefaultClaims()
    {
        $payload = new Payload($this->request, $this->payloadUtilities, $this->payloadValidator);
        $payload->setClaim('sub', 'subject');

        $this->assertSame('subject', $payload->getClaim('sub'));
        $this->assertSame(1, $payload->getClaim('iat'));
        $this->assertSame(3601, $payload->getClaim('exp'));
        $this->assertSame(1, $payload->getClaim('nbf'));
        $this->assertSame('http://some.url.com', $payload->getClaim('iss'));
        $this->assertSame(sha1(1 . 'subject'), $payload->getClaim('jti'));
    }

    /**
     * @test
     * @group payload
     */
    public function customClaimsShouldBeAddedToClaims()
    {
        $payload = new Payload($this->request, $this->payloadUtilities, $this->payloadValidator, array('iat', 'exp', 'nbf', 'iss', 'jti'));
        $payload->setClaims(array('scopes' => array('hr' => array('admin', 'user' => array('create', 'read')))));
        $claims = $payload->getClaims();

        $this->assertArrayHasKey('scopes', $claims);
    }

    /**
     * @test
     * @group payloadJti
     */
    public function checkThatJtiIsRecalculatedWheneverSubOrIatClaimsAreUpdated()
    {
        $payload = new Payload($this->request, $this->payloadUtilities, $this->payloadValidator, array('iat', 'exp', 'nbf', 'iss', 'jti'));

        $this->assertSame(sha1(1 . 'a1b2c3d4'), $payload->getClaim('jti'));

        $payload->setClaim('sub', 'subject');
        $this->assertSame(sha1(1 . 'subject'), $payload->getClaim('jti'));

        $payload->setClaim('iat', 123456789);
        $this->assertSame(sha1(123456789 . 'subject'), $payload->getClaim('jti'));
    }

    /**
     * @test
     * @group payload
     */
    public function getPayloadShouldCallValidateClaims()
    {
        $this->payloadValidator->shouldReceive('validateClaims')->once();

        $payload = new Payload($this->request, $this->payloadUtilities, $this->payloadValidator);
        $payload->getPayload();
    }

    /**
     * @test
     * @group payload
     */
    public function verifyDefaultClaimsAppearInPayload()
    {
        $this->payloadValidator->shouldReceive('validateClaims')->once();

        $payload = new Payload($this->request, $this->payloadUtilities, $this->payloadValidator);
        $payloadContents = $payload->getPayload();

        $this->assertTrue(count(array_diff(array_values(array('iat', 'exp', 'nbf', 'iss', 'jti')), array_keys($payloadContents))) === 0);
    }
}
