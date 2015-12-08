<?php

use Bendbennett\JWT\Validators\PayloadValidator;

class PayloadValidatorTest extends PHPUnit_Framework_TestCase
{

    public function tearDown()
    {
        Mockery::close();
    }

    /**
     * @test
     * @expectedException \Exception
     * @group payloadValidator
     */
    public function exceptionShouldBeThrownIfRequiredClaimIsMissing()
    {
        $payloadValidator = new PayloadValidator();
        $payloadValidator->validateClaims(array('missingClaim'), array(), array());
    }

    /**
     * @test
     * @expectedException \Exception
     * @group payloadValidator
     */
    public function exceptionShouldBeThrownIfRequiredClaimIsSetButIsNotAKeyValuePair()
    {
        $payloadValidator = new PayloadValidator();
        $payloadValidator->validateClaims(array('claimOnlyHasKeyButNoValue'), array(), array('claimOnlyHasKeyButNoValue'));
    }

    /**
     * @test
     * @expectedException \Exception
     * @group payloadValidator
     */
    public function exceptionShouldBeThrownIfRequiredClaimIssetButIsEmpty()
    {
        $payloadValidator = new PayloadValidator();
        $payloadValidator->validateClaims(array('emptyClaim'), array(), array('emptyClaim' => ''));
    }

    /**
     * @test
     * @group payloadValidator
     */
    public function shouldReturnTrueIfRequiredClaimIssetAndIsZeroAsInt()
    {
        $payloadValidator = new PayloadValidator();
        $this->assertTrue($payloadValidator->validateClaims(array('requiredClaim'), array(), array('requiredClaim' => 0)));
    }

    /**
     * @test
     * @group payloadValidator
     */
    public function shouldReturnTrueIfRequiredClaimIssetAndIsZeroAsFloat()
    {
        $payloadValidator = new PayloadValidator();
        $this->assertTrue($payloadValidator->validateClaims(array('requiredClaim'), array(), array('requiredClaim' => 0.0)));
    }

    /**
     * @test
     * @group payloadValidator
     */
    public function shouldReturnTrueIfRequiredClaimIssetAndIsZeroAsString()
    {
        $payloadValidator = new PayloadValidator();
        $this->assertTrue($payloadValidator->validateClaims(array('requiredClaim'), array(), array('requiredClaim' => '0')));
    }

    /**
     * @test
     * @expectedException \Exception
     * @group payloadValidator
     */
    public function shouldThrowExceptionIfRequiredClaimIsNull()
    {
        $payloadValidator = new PayloadValidator();
        $this->assertTrue($payloadValidator->validateClaims(array('requiredClaim'), array(), array('requiredClaim' => null)));
    }

    /**
     * @test
     * @expectedException \Exception
     * @group payloadValidator
     */
    public function shouldThrowExceptionIfRequiredClaimIsFalse()
    {
        $payloadValidator = new PayloadValidator();
        $this->assertTrue($payloadValidator->validateClaims(array('requiredClaim'), array(), array('requiredClaim' => false)));
    }

}
