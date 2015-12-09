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

    protected $payload;


    /**
     * Using a wrapper to proxy Namshi\JOSE\JWS so can unit test the JWT::read() method
     * as this contains a call to the static JWS::load() method
     *
     * @param JWSProxy $jws
     * @param Factory $algoFactory
     * @param Payload $payload
     */
    public function __construct(JWSProxy $jws, Factory $algoFactory, Payload $payload)
    {
        $this->jws = $jws;
        $this->algoFactory = $algoFactory;
        $this->payload = $payload;
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
     * @param $token
     * @return array
     */
    public function read($request)
    {
        $token = $this->getAuthorizationHeader($request);

        $this->jws = $this->jws->callLoad($token);
        $algo = $this->algoFactory->make();

        if ($this->jws->verify($algo->getKeyForVerifying())) {
            return $this->jws->getPayload();
        }
    }


    /**
     * Scopes take form of nested JSON @link https://auth0.com/blog/2014/12/02/using-json-web-tokens-as-api-keys/
     *
     * scopes: { api: { role: { actions: [] } } }
     * for example: scopes: { hr: { user: { actions: ['read', 'create'] }, admin } }
     *
     * $scope takes form of dot separated string used in routes e.g., hr.user.create
     *
     * @param $requiredScopes
     * @param $authorizationHeader
     * @return bool
     * @throws \Exception
     */
    public function hasScope($requiredScopes, $request)
    {
        $hasScope = false;

        //need to trap for errors here;
        $token = $this->getAuthorizationHeader($request);
        $payload = $this->read($token);

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
            } elseif (in_array($explodedScope[$i], $payloadScopes) && $i == $explodedScopeCount -1) {
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