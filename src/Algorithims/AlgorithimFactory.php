<?php

namespace Bendbennett\JWT\Algorithims;

use Bendbennett\JWT\Factory;

class AlgorithimFactory implements Factory
{
    protected $algorithim;
    protected $secret;
    protected $privateKey;
    protected $publicKey;

    public $allowedSymmetricAlgorithms = array('HS256', 'HS384', 'HS512');
    public $allowedAsymmetricAlgorithms = array('ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512');

    public function __construct(array $config)
    {
        $this->algorithim = $config['algorithim'];
        $this->secret = $config['secret'];
        $this->privateKey = $config['privateKey'];
        $this->publicKey = $config['publicKey'];
    }

    //need to check whether there's anyway to determine on basis of implemented/extended class as to whether to use symmetric or asymmetric algo
    //need a specific exception for this error
    public function make()
    {
        if (!in_array($this->algorithim, array_merge($this->allowedSymmetricAlgorithms, $this->allowedAsymmetricAlgorithms))) {
            throw new \Exception('not an allowed algo');
        }

        if (in_array($this->algorithim, $this->allowedSymmetricAlgorithms)) {
            return new SymmetricAlgorithim($this->secret);
        } else {
            return new AsymmetricAlgorithim($this->privateKey, $this->publicKey, base_path());
        }
    }
}