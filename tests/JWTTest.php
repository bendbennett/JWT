<?php

use Bendbennett\JWT\JWT;
use Bendbennett\JWT\Jti;

use Mockery\Mock;

class JWTTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var \Bendbennett\JWT\JWSProxy|\Mockery\MockInterface $jwsProxy
     */
    protected $jwsProxy;

    /**
     * @var \Mockery\MockInterface
     */
    protected $algo;

    /**
     * @var Bendbennett\JWT\Algorithms\AlgorithmFactory|\Mockery\MockInterface $algoFactory
     */
    protected $algoFactory;

    /**
     * @var \Mockery\MockInterface
     */
    protected $payload;

    /**
     * @var \Mockery\MockInterface
     */
    protected $jwtPartialMock;

    /**
     * @var \Mockery\MockInterface
     */
    protected $jti;

    /**
     * @var \Mockery\MockInterface
     */
    protected $request;

    public function setUp()
    {
        $this->jwsProxy = Mockery::mock('Bendbennett\JWT\JWSProxy');
        $this->algo = Mockery::mock('Bendbennett\JWT\Algorithms\AsymmetricAlgorithm');
        $this->algoFactory = Mockery::mock('Bendbennett\JWT\Algorithms\AlgorithmFactory');
        $this->payload = Mockery::mock('Bendbennett\JWT\Payload');
        $this->jti = Mockery::mock('Bendbennett\JWT\Jti');
        $this->jwtPartialMock = Mockery::mock('Bendbennett\JWT\JWT[read, getAuthorizationHeader]', array($this->jwsProxy, $this->algoFactory, $this->payload, 'algoDefinedInConfig', $this->jti));
        $this->request = Mockery::mock('\Illuminate\Http\Request');
    }

    public function tearDown()
    {
        Mockery::close();
    }

    /**
     * @test
     * @group jwt
     */
    public function createShouldCallRelevantMethods()
    {
        $this->jwsProxy->shouldReceive('setPayload')->once();
        $this->jwsProxy->shouldReceive('sign')->once();
        $this->jwsProxy->shouldReceive('getTokenString')->once();

        $this->algo->shouldReceive('getKeyForSigning')->once();

        $this->algoFactory->shouldReceive('make')->once()->andReturn($this->algo);

        $this->payload->shouldReceive('setClaims')->once();
        $this->payload->shouldReceive('getPayload')->once()->andReturn(array());
        $this->payload->shouldReceive('getClaim')->twice();

        $this->jti->shouldReceive('create')->once();

        $jwt = new JWT($this->jwsProxy, $this->algoFactory, $this->payload, 'algoDefinedInConfig', $this->jti);
        $jwt->create(array());
    }

    /**
     * @test
     * @group jwt
     */
    public function readShouldCallRelevantMethods()
    {
        $this->jwsProxy->shouldReceive('callLoad')->once()->andReturn($this->jwsProxy);
        $this->jwsProxy->shouldReceive('verify')->once()->andReturn(true);
        $this->jwsProxy->shouldReceive('isExpired')->once()->andReturn(false);
        $this->jwsProxy->shouldReceive('getPayload')->once()->andReturn(true);

        $this->algo->shouldReceive('getKeyForVerifying')->twice()->andReturn(true);

        $this->algoFactory->shouldReceive('make')->once()->andReturn($this->algo);

        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');

        $jwt = new JWT($this->jwsProxy, $this->algoFactory, $this->payload, 'algoDefinedInConfig', $this->jti);
        $jwt->read($this->request);
    }

    /**
     * @test
     * @group jwt
     */
    public function hasScopeShouldReturnTrueWhenTokenContainsRole()
    {
        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwtPartialMock->shouldReceive('read')->once()->andReturn(array('scopes' => array('hr' => array('user'))));

        $this->assertTrue($this->jwtPartialMock->hasScope(array('hr.user'), $this->request));
    }

    /**
     * @test
     * @group jwt
     */
    public function hasScopeShouldReturnTrueWhenTokenContainsRoleAndAction()
    {
        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwtPartialMock->shouldReceive('read')->once()->andReturn(array('scopes' => array('hr' => array('user' => array('create')))));

        $this->assertTrue($this->jwtPartialMock->hasScope(array('hr.user.create'), $this->request));
    }

    /**
     * @test
     * @group jwt
     */
    public function hasScopeShouldReturnTrueWhenTokenContainsRoleAndAdditionalActions()
    {
        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwtPartialMock->shouldReceive('read')->once()->andReturn(array('scopes' => array('hr' => array('user' => array('create')))));

        $this->assertTrue($this->jwtPartialMock->hasScope(array('hr.user'), $this->request));
    }

    /**
     * @test
     * @group jwt
     */
    public function hasScopeShouldReturnFalseWhenTokenDoesNotContainsRole()
    {
        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwtPartialMock->shouldReceive('read')->once()->andReturn(array('scopes' => array('hr' => array('user'))));

        $this->assertFalse($this->jwtPartialMock->hasScope(array('hr.admin'), $this->request));
    }

    /**
     * @test
     * @group jwt
     */
    public function hasScopeShouldReturnFalseWhenTokenDoesNotContainsRoleButDoesContainAdditionalActions()
    {
        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwtPartialMock->shouldReceive('read')->once()->andReturn(array('scopes' => array('hr' => array('user' => array('create')))));

        $this->assertFalse($this->jwtPartialMock->hasScope(array('hr.admin'), $this->request));
    }

    /**
     * @test
     * @group jwt
     */
    public function hasScopeShouldReturnFalseWhenTokenDoesNotContainAnyMatchingEntries()
    {
        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwtPartialMock->shouldReceive('read')->once()->andReturn(array('scopes' => array('hr' => array('admin'))));

        $this->assertFalse($this->jwtPartialMock->hasScope(array('something.else.entirely'), $this->request));
    }

    /**
     * @test
     * @group jwt
     */
    public function hasScopeShouldReturnTrueWhenTokenContainsMatchingEntry()
    {
        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwtPartialMock->shouldReceive('read')->once()->andReturn(array('scopes' => array('hr' => array('admin'))));

        $this->assertTrue($this->jwtPartialMock->hasScope(array('something.else.entirely', 'hr.admin'), $this->request));
    }

    /**
     * @test
     * @group jwt
     */
    public function hasScopeShouldReturnTrueWhenTokenContainsMatchingEntryWithArbitraryNesting()
    {
        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwtPartialMock->shouldReceive('read')->once()->andReturn(array('scopes' => array('api' => array('role' => array('actions' => array('read'))))));

        $this->assertTrue($this->jwtPartialMock->hasScope(array('something.else.entirely', 'api.role.actions.read'), $this->request));
    }

    /**
     * @test
     * @group jwtnew
     * @expectedException \Exception
     */
    public function readShouldThrowExceptionWhenVerificationOfJWTReturnsFalse()
    {
        $this->request->shouldReceive('header')->once()->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwsProxy->shouldReceive('callLoad')->once()->andReturn($this->jwsProxy);
        $algo = Mockery::mock('Bendbennett\JWT\Algorithms\AsymmetricAlgorithm');
        $algo->shouldReceive('getKeyForVerifying')->once();
        $this->algoFactory->shouldReceive('make')->once()->andReturn($algo);
        $this->jwsProxy->shouldReceive('verify')->once()->andReturn(false);

        $jwt = new JWT($this->jwsProxy, $this->algoFactory, $this->payload, 'algoDefinedInConfig', $this->jti);
        $jwt->read($this->request);
    }

    /**
     * @test
     * @group jwtnew
     * @expectedException \Exception
     */
    public function readShouldThrowExceptionWhenValidationOfJWTReturnsFalse()
    {
        $this->request->shouldReceive('header')->once()->with('Authorization')->andReturn('Bearer abcd1234');
        $this->jwsProxy->shouldReceive('callLoad')->once()->andReturn($this->jwsProxy);
        $algo = Mockery::mock('Bendbennett\JWT\Algorithms\AsymmetricAlgorithm');
        $algo->shouldReceive('getKeyForVerifying')->twice();
        $this->algoFactory->shouldReceive('make')->once()->andReturn($algo);
        $this->jwsProxy->shouldReceive('verify')->once()->andReturn(true);
        $this->jwsProxy->shouldReceive('isExpired')->once()->andReturn('false');

        $jwt = new JWT($this->jwsProxy, $this->algoFactory, $this->payload, 'algoDefinedInConfig', $this->jti);
        $jwt->read($this->request);
    }

}

