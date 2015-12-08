<?php

namespace Bendbennett\JWT\Utilities;

use Carbon\Carbon;

class PayloadUtilities implements PayloadUtilitiesInterface
{
    protected $now;

    protected $ttl;

    public function __construct($ttl)
    {
        $this->now = Carbon::now()->getTimestamp();
        $this->ttl = $ttl;
    }

    public function getIat()
    {
        return $this->now;
    }

    public function getExp()
    {
        return Carbon::createFromTimestamp($this->now)->addMinute($this->ttl)->getTimestamp();
    }

    public function getNbf()
    {
        return $this->now;
    }
}