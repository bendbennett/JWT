<?php

use Bendbennett\JWT\Utilities\PayloadUtilities;

class PayloadUtilitiesTest extends PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        Mockery::close();
    }

    /**
     * @test
     * @group payloadUtilities
     */
    public function getExpShouldBeTtlMinutesAfterIat()
    {
        $ttl = 60;
        $payloadUtilities = new PayloadUtilities($ttl);
        $this->assertEquals($payloadUtilities->getIat() + 3600, $payloadUtilities->getExp());
    }
}
