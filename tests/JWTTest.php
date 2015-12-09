<?php

use Bendbennett\JWT\JWT;
use Bendbennett\JWT\Payload;
use Namshi\JOSE\JWS;

class JWTTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var \Mockery\MockInterface|\Bendbennett\JWT\JWSProxy
     */
    protected $jwsProxy;

    /**
     * @var \Mockery\MockInterface
     */
    protected $algo;

    /**
     * @var \Mockery\MockInterface|Bendbennett\JWT\Factory
     */
    protected $algoFactory;

    /**
     * @var \Mockery\MockInterface|Bendbennett\JWT\Payload
     */
    protected $payload;

    /**
     * @var \Mockery\MockInterface|Bendbennett\JWT\JWT
     */
    protected $jwtPartialMock;

    /**
     * @var \Mockery\MockInterface
     */
    protected $request;

    public function setUp()
    {
        $this->jwsProxy = Mockery::mock('Bendbennett\JWT\JWSProxy');
        $this->algo = Mockery::mock('Bendbennett\JWT\Algorithims\AsymmetricAlgorithim');
        $this->algoFactory = Mockery::mock('Bendbennett\JWT\Algorithims\AlgorithimFactory');
        $this->payload = Mockery::mock('Bendbennett\JWT\Payload');
        $this->jwtPartialMock = Mockery::mock('Bendbennett\JWT\JWT[read, getAuthorizationHeader]', array($this->jwsProxy, $this->algoFactory, $this->payload));
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

        $jwt = new JWT($this->jwsProxy, $this->algoFactory, $this->payload);
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
        $this->jwsProxy->shouldReceive('getPayload')->once()->andReturn(true);

        $this->algo->shouldReceive('getKeyForVerifying')->once()->andReturn(true);

        $this->algoFactory->shouldReceive('make')->once()->andReturn($this->algo);

        $this->request->shouldReceive('header')->with('Authorization')->andReturn('Bearer abcd1234');

        $jwt = new JWT($this->jwsProxy, $this->algoFactory, $this->payload);
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
}

