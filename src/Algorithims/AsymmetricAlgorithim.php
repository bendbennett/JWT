<?php

namespace Bendbennett\JWT\Algorithims;

    //looks for file in directory in the root of the laravel directory i.e., 1 level up from /app using relative path
    //tries to load from anywhere within the file system using absolute path
    //tries to load the key using the string defined in the config directory


/**
 * Class AsymmetricAlgo
 * @package Bendbennett\JWT\Providers
 */
class AsymmetricAlgorithim implements AlgorithimInterface
{
    protected $privateKey;
    protected $publicKey;
    protected $basePath;
    protected $relativePathPrefix;
    protected $absolutePathPrefix;

    public function __construct($privateKey, $publicKey, $basePath)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
        $this->basePath = $basePath;
        $this->relativePathPrefix = "file:///" . $this->basePath . '/';
        $this->absolutePathPrefix = "file://";
    }

    /**
     * @return bool|resource
     * @throws \Exception
     */
    public function getKeyForSigning()
    {
        if ($keyResource = openssl_pkey_get_private($this->relativePathPrefix . $this->privateKey)) {
            return $keyResource;
        } elseif ($keyResource = openssl_pkey_get_private($this->absolutePathPrefix . $this->privateKey)) {
            return $keyResource;
        } elseif ($keyResource = openssl_pkey_get_private($this->privateKey)) {
            return $keyResource;
        } else {
            throw new \Exception('cannot read private key file');
        }
    }

    /**
     * @return resource
     * @throws \Exception
     */
    public function getKeyForVerifying()
    {
        if ($keyResource = openssl_pkey_get_public($this->relativePathPrefix . $this->publicKey)) {
            return $keyResource;
        } elseif ($keyResource = openssl_pkey_get_public($this->absolutePathPrefix . $this->publicKey)) {
            return $keyResource;
        } elseif ($keyResource = openssl_pkey_get_public($this->publicKey)) {
            return $keyResource;
        } else {
            throw new \Exception('cannot read public key file');
        }
    }

}