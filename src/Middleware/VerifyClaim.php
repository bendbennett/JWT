<?php

namespace Bendbennett\JWT\Middleware;

use Bendbennett\JWT\JWT;
use Closure;
use Illuminate\Http\JsonResponse;

class VerifyClaim
{

    /**
     * @var JWT
     */
    protected $jwt;

    /**
     * @param JWT $jwt
     */
    public function __construct(JWT $jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * @param \Illuminate\Http\Request $request
     * @param Closure $next
     * @param ...$roles
     * @return JsonResponse
     * @throws \Exception
     */
    public function handle($request, Closure $next, ...$roles)
    {
        if (! $this->jwt->hasScope($roles, $request)) {
            return new JsonResponse([
                'success' => false,
                'message' => 'permission denied'
            ],403);
        }

        return $next($request);
    }
}