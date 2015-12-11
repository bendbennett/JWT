<?php

namespace Bendbennett\JWT\Providers;

use Bendbennett\JWT\Jti;
use Bendbennett\JWT\JWSProxy;
use Bendbennett\JWT\JWT;
use Bendbennett\JWT\Payload;

use Bendbennett\JWT\Algorithms\AlgorithmFactory;
use Bendbennett\JWT\Utilities\PayloadUtilities;
use Bendbennett\JWT\Validators\PayloadValidator;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;
use Namshi\JOSE\JWS;

class JWTServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Perform post-registration booting of services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/../config/config.php' => config_path('jwtbdb.php')
        ], 'config');

        $this->publishes([
            __DIR__ . '/../database/migrations/' => database_path('migrations')
        ], 'migrations');


        $this->app['Bendbennett\JWT\JWT'] = function ($app) {
            return $app['bendbennett.jwt'];
        };

//        $this->app['Bendbennett\JWT\Providers\JWTAlgoFactory'] = function ($app) {
//            return $app['bendbennett.jwtalgofactory'];
//        };
//
//        $this->app['Bendbennett\JWT\JWSProxy'] = function ($app) {
//            return $app['bendbennett.jwsproxy'];
//        };
//
//        $this->app['Bendbennett\JWT\Payload'] = function ($app) {
//            return $app['bendbennett.payload'];
//        };
//
//        $this->app['Bendbennett\JWT\Helpers\Utilities'] = function ($app) {
//            return $app['bendbennett.utilities'];
//        };


        // use the vendor configuration file as fallback
        // $this->mergeConfigFrom(
        //     __DIR__.'/config/config.php', 'JWT'
        // );
    }

    /**
     * Define the routes for the application.
     *
     * @param  \Illuminate\Routing\Router $router
     * @return void
     */
    public function setupRoutes(Router $router)
    {
//        $router->group(['namespace' => 'Bendbennett\JWT\Http\Controllers'], function($router)
//        {
//            require __DIR__.'/Http/routes.php';
//        });
    }

    /**
     * Register any package services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerJWT();
        $this->registerJWSProxy();
        $this->registerJWTAlgoFactory();
        $this->registerPayload();
        $this->registerPayloadValidator();
        $this->registerPayloadUtilities();

        // use this if your package has a config file
        // config([
        //         'config/JWT.php',
        // ]);
    }

    // this works for registering interfaces but cannot be used as is for registering name (as below)
    // $this->app->bind('Bendbennett\\JWT\\JWTInterface', 'Bendbennett\\JWT\\JWT');

//        $this->app->bind('JWT',function($app){
//            return new JWT($app);
//        });

    //hard dependency on JWS embedded in this register call - look at interfaces etc
    private function registerJWT()
    {
        $this->app['bendbennett.jwt'] = $this->app->share(function ($app) {
            return new JWT($app['bendbennett.jwsproxy'], $app['bendbennett.jwtalgofactory'], $app['bendbennett.payload'], config('jwtbdb.algorithm'), new Jti());
        });
    }

    private function registerJWSProxy()
    {
        $this->app['bendbennett.jwsproxy'] = $this->app->share(function ($app) {
            return new JWSProxy([
                'typ' => 'JWT',
                'alg' => config('jwtbdb.algorithm'),
            ]);
        });
    }

    private function registerJWTAlgoFactory()
    {
        $this->app['bendbennett.jwtalgofactory'] = $this->app->share(function ($app) {
            return new AlgorithmFactory(array(
                'algorithm' => config('jwtbdb.algorithm'),
                'secret' => config('jwtbdb.secret'),
                'privateKey' => config('jwtbdb.privateKey'),
                'publicKey' => config('jwtbdb.publicKey'),
            ));
        });
    }

    private function registerPayload()
    {
        $this->app['bendbennett.payload'] = $this->app->share(function ($app) {
            return new Payload(
                $app['request'],
                $app['bendbennett.utilities.payloadutilities'],
                $app['bendbennett.validators.payloadvalidator'],
                config('jwtbdb.requiredClaims'));
        });
    }

    private function registerPayloadUtilities()
    {
        $this->app['bendbennett.utilities.payloadutilities'] = $this->app->share(function () {
            return new PayloadUtilities(
                config('jwtbdb.ttl'));
        });
    }

    private function registerPayloadValidator()
    {
        $this->app['bendbennett.validators.payloadvalidator'] = $this->app->share(function ($app) {
            return new PayloadValidator();
        });
    }
}