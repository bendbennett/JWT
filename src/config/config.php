<?php

return [

    /*
    |--------------------------------------------------------------------------
    | JWT Algorithim
    |--------------------------------------------------------------------------
    |
    | This is the algorithm used to sign JWT.
    | Set this to the desired algorithm.
    | Acceptable values are ES256/384/512, HS256/384/512, RS256/384/512 - see Namshi etc........
    | A helper command is provided for this: `php artisan jwt:generate`
    |
    */

    'algorithim' => 'ES256',

    'privateKey' => '',

    'publicKey' => '',

    'ttl' => '',

    'secret' => '',

    'requiredClaims' => ['iss', 'iat', 'exp', 'nbf', 'sub', 'jti'],

];
