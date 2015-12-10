<?php

namespace Bendbennett\JWT;

use Bendbennett\JWT\Algorithims\AlgoritihimFactory;

/**
 * Class JWT
 * @package Bendbennett\JWT
 */
class JWT implements JWTInterface
{
    /**
     * @var JWSProxy
     */
    protected $jws;

    /**
     * @var Factory
     */
    protected $algoFactory;

    /**
     * @var Payload
     */
    protected $payload;

    /**
     * @var string
     */
    protected $algoritihim;

    /**
     * Using a wrapper to proxy Namshi\JOSE\JWS so can unit test the JWT::read() method
     * as this contains a call to the static JWS::load() method
     *
     * @param JWSProxy $jws
     * @param Factory $algoFactory
     * @param Payload $payload
     * @param String $algorithim
     */
    public function __construct(JWSProxy $jws, Factory $algoFactory, Payload $payload, $algorithim)
    {
        $this->jws = $jws;
        $this->algoFactory = $algoFactory;
        $this->payload = $payload;
        $this->algoritihim = $algorithim;
    }

    /**
     * Claims is an additional set of claims supplied by end-user
     * There are default claims in Payload class
     * If end-user supplies claims with same name as default claims, the default claims in the Payload class will be overwritten
     *
     * @param array $claims
     * @return string
     */
    public function create(array $claims = array())
    {
        $this->payload->setClaims($claims);
        $this->jws->setPayload($this->payload->getPayload());

        $algo = $this->algoFactory->make();
        $this->jws->sign($algo->getKeyForSigning());

        return $this->jws->getTokenString();
    }

    /**
     * @param $request
     * @return array
     * @throws \Exception
     */
    public function read($request)
    {
        $token = $this->getAuthorizationHeader($request);

        $this->jws = $this->jws->callLoad($token);
        $algo = $this->algoFactory->make();

        if (!$this->jws->verify($algo->getKeyForVerifying(), $this->algoritihim)) {
            throw new \Exception('JWT algoritihim used for signing does not match algoritihim used for verifying');
        }

        if ($this->jws->isExpired($algo->getKeyForVerifying(), $this->algoritihim)) {
            throw new \Exception('JWT has expired');
        }

        return $this->jws->getPayload();
    }

    /**
     * @param $request
     * @return mixed
     * @throws \Exception
     */
    private function getAuthorizationHeader($request)
    {
        if (is_null($authorizationHeader = $request->header('Authorization'))) {
            throw new \Exception('Authorization header is either missing or empty');
        }

        if (strpos($authorizationHeader, 'Bearer ') === false) {
            throw new \Exception('Authorization header is malformed and does not contain "Bearer"');
        }

        return str_replace('Bearer ', '', $authorizationHeader);
    }

    /**
     * Scopes take form of nested JSON @link https://auth0.com/blog/2014/12/02/using-json-web-tokens-as-api-keys/
     * i.e., scopes: { api: { role: [action1, action2] } }
     * e.g., scopes: { hr: { user: ['read', 'create'] } }
     *
     * Roles without specified actions are also allowed
     * i.e., scopes: { api: { role1: [action1, action2], role2 } }
     * e.g., scopes: { api: { user: [read, create], admin } }
     *
     * Scopes take form of dot separated string when used in routes (e.g., hr.user.create)
     *
     * In order for a user to be allowed to access a specific route there must be an exact match between the scopes in the JWT
     * and the required scope(s) defined on the route
     * for example
     * Route::get('/', 'DefaultController@index')->middleware(['middleware' => 'verifyClaim:hr.user.read']);
     * requires payload to contain
     * scopes: { hr: { user: [read] } }
     *
     * $requiredScopes is an array of scopes defined on the route(s) (e.g., hr.user.read,hr.admin)
     * $request should contain Authorization header containing JWT
     *
     * @param $requiredScopes
     * @param $request
     * @return bool
     * @throws \Exception
     */
    public function hasScope(array $requiredScopes, $request)
    {
        $hasScope = false;

        //need to trap for errors here;
        $payload = $this->read($request);

        if (isset ($payload['scopes'])) {
            $payloadScopes = $payload['scopes'];
        } else {
            throw new \Exception('scopes is missing from the token payload');
        }

        foreach ($requiredScopes as $scope) {
            $explodedScope = explode('.', $scope);

            if ($this->checkScope($explodedScope, $payloadScopes)) {
                $hasScope = true;
                break;
            }
        }
        return $hasScope;
    }

    /**
     * checkScope() is called recursively to determine whether there is scope within the JWT payload that matches
     * a scope defined on the route
     *
     * There is also a check to determine whether the scope contained within the payload match the route scope
     * in cases where the payload scope has additional properties
     * e.g., route scope == hr.user, payload scope == scopes: { hr : { user: [read] } } will return true because the JWT
     * contains an hr.user scope albeit with additional actions
     *
     * @param $explodedScope
     * @param $payloadScopes
     * @return bool
     */
    private function checkScope($explodedScope, $payloadScopes)
    {
        $explodedScopeCount = count($explodedScope);

        if ($explodedScopeCount === 0 && count($payloadScopes) > 0) {
            return true;
        }

        for ($i = 0; $i < $explodedScopeCount; $i++) {
            if (isset($payloadScopes[$explodedScope[$i]]) && is_array($payloadScopes[$explodedScope[$i]])) {
                $payloadScopes = $payloadScopes[$explodedScope[$i]];
                $explodedScope = array_splice($explodedScope, 1);
                return $this->checkScope($explodedScope, $payloadScopes);
            } elseif (in_array($explodedScope[$i], $payloadScopes) && $i == $explodedScopeCount - 1) {
                return true;
            } else {
                return false;
            }
        }
    }

    /**
     * @param $token
     */
    public function isRevoked($token)
    {

    }

    /**
     * @param $token
     */
    public function isExpired($token)
    {

    }

    /**
     * @param $token
     */
    public function revoke($token)
    {

    }

    /**
     * @param $token
     */
    public function refresh($token)
    {

    }

}