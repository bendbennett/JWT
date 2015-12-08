<?php

namespace Bendbennett\JWT;

use Bendbennett\JWT\Utilities\PayloadUtilitiesInterface;
use Bendbennett\JWT\Validators\PayloadValidatorInterface;
use Illuminate\Http\Request;

class Payload implements PayloadInterface
{
    /**
     * Subject and audience have not been implemented within the Payload class
     *
     * Subject - typically user associated with the JWT - Optional
     * @link https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.2
     * @var string
     *
     *
     * Audience - typically, audience(s) of this token - Optional
     * @link https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.3
     * @var string
     *
     *
     * https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
     */

    protected $defaultClaims = array(
        'iat' => 'int',
        'exp' => 'int',
        'nbf' => 'int',
        'iss' => 'string',
        'jti' => 'string',
    );

    protected $claims = array();

    protected $recalculateJtiClaims = array('sub', 'iat');

    protected $request;

    protected $payloadUtilities;

    protected $payloadValidator;

    protected $requiredClaims = array();

    public function __construct(Request $request, PayloadUtilitiesInterface $payloadUtilities, PayloadValidatorInterface $payloadValidator,  array $requiredClaims = array())
    {
        $this->request = $request;
        $this->payloadUtilities = $payloadUtilities;
        $this->payloadValidator = $payloadValidator;
        $this->requiredClaims = $requiredClaims;

        $this->setDefaultClaims();
    }

    protected function setDefaultClaims()
    {
        foreach ($this->defaultClaims as $key => $value) {
            $this->$key();
        }
    }

    /**
     * Issued At - identifies the time at which the claim was issued
     * Optional - https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.5
     * @var int
     */
    private function iat()
    {
        $this->claims['iat'] = $this->payloadUtilities->getIat();
    }

    /**
     * Expiration time - identifies the expiration time of the token after which the JWT must not be accepted for processing
     * Optional - https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.4
     * @var int
     */
    private function exp()
    {
        $this->claims['exp'] = $this->payloadUtilities->getExp();
    }

    /**
     * Not Before - identifies time before which the JWT must not be accepted for processing
     * Optional - https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.5
     * @var int
     */
    private function nbf()
    {
        $this->claims['nbf'] = $this->payloadUtilities->getNbf();
    }

    /**
     * Issuer - typically a URI indicating the service that issued the token
     * Optional - https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.1
     * @var string
     */
    private function iss()
    {
        $this->claims['iss'] = $this->request->url();
    }

    /**
     * JWT id - unique identifier for the JWT
     * Optional - https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#rfc.section.4.1.7
     *
     * If 'sub' (e.g., user ID) claim is present within the $claims array, then it is used with 'iat' to generate 'jti' claim,
     * otherwise uniqid() is used.
     */
    private function jti()
    {
        if (isset($this->claims['sub'])) {
            $this->claims['jti'] = sha1($this->claims['iat'] . $this->claims['sub']);
        } else {
            $this->claims['jti'] = sha1($this->claims['iat'] . uniqid('', true));
        }
    }

    public function getClaim($key)
    {
        if (array_key_exists($key, $this->claims)) {
            return $this->claims[$key];
        } else {
            return false;
        }
    }

    public function getClaims()
    {
        return $this->claims;
    }

    public function setClaim($key, $value)
    {
        $this->claims[$key] = $value;

        if (in_array($key, $this->recalculateJtiClaims)) {
            $this->jti();
        }
    }

    public function setClaims(array $claims)
    {
        foreach ($claims as $key => $value) {
            $this->claims[$key] = $value;

            if (in_array($key, $this->recalculateJtiClaims)) {
                $this->jti();
            }
        }
    }

    public function getPayload()
    {
        $this->payloadValidator->validateClaims($this->requiredClaims, $this->defaultClaims, $this->claims);

        return $this->claims;
    }

}