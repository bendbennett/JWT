<?php

namespace Bendbennett\JWT\Validators;

class PayloadValidator implements PayloadValidatorInterface
{
    public function validateClaims(array $requiredClaims, array $defaultClaims, array $claims)
    {
        $this->checkRequiredClaimsAreSet($requiredClaims, $claims);
        $this->checkRequiredClaimsAreNotEmpty($requiredClaims, $claims);
        $this->checkDefaultClaimsAreSetAndCorrectType($defaultClaims, $claims);

        return true;
    }

    protected function checkRequiredClaimsAreSet(array $requiredClaims, array $claims) {
        $missingRequiredClaims = array_diff(array_values($requiredClaims), array_keys($claims));

        if (count($missingRequiredClaims) !== 0) {
            $missingClaims = array();

            foreach ($missingRequiredClaims as $missingRequiredClaim) {
                array_push($missingClaims, $missingRequiredClaim);
            }

            throw new \Exception('"' . implode(', ', $missingClaims) . '" required claim(s) missing');
        }

        return true;
    }

    protected function checkRequiredClaimsAreNotEmpty($requiredClaims, $claims)
    {
        foreach ($requiredClaims as $requiredClaim) {
            if (empty($claims[$requiredClaim]) && strlen((string) $claims[$requiredClaim]) === 0) {
                throw new \Exception('"'. $requiredClaim .'" is empty');
            }
        }

        return true;
    }

    protected function checkDefaultClaimsAreSetAndCorrectType($defaultClaims, $claims)
    {
        foreach ($claims as $key => $value) {
            if (!array_key_exists($key, $defaultClaims)) {
                continue;
            }

            if ($defaultClaims[$key] == 'string') {
                $this->verifyString($key, $claims[$key]);
            } elseif ($defaultClaims[$key] == 'int') {
                $this->verifyInteger($key, $claims[$key]);
            }
        }
    }

    private function verifyString($key, $value)
    {
        if (!is_string($value) || $this->lengthZero($value)) {
            throw new \Exception($key . ' is not a string or has zero length');
        }
    }

    private function lengthZero($value)
    {
        if (strlen($value) === 0) {
            return true;
        } else {
            return false;
        }
    }

    private function verifyInteger($key, $value)
    {
        if (!is_int($value)) {
            throw new \Exception($key . ' is not an integer');
        }
    }
}