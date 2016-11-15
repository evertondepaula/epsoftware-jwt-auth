<?php

namespace Epsoftware\Auth\Providers;

use Epsoftware\Auth\Middlewares\MiddlewareAuth;
use Illuminate\Support\ServiceProvider;
use Epsoftware\Auth\Auth as Auth;
use Epsoftware\Auth\JWT as JWT;

class AuthServiceProvider extends ServiceProvider
{
	protected $config;

	public function register()
	{
		$this->mergeConfigFrom(
			__DIR__.'/../../config/epsoftware-jwt-auth.php', 'epsoftware-jwt-auth'
		);

		$this->app->singleton('epsoftware.auth', function() {
			return new Auth();
		});

		$this->app->singleton('epsoftware.jwt', function() {
			return new JWT();
		});
	}

	public function boot()
	{
		$this->publishes([
			__DIR__.'/../../config/epsoftware-jwt-auth.php' => base_path('config/epsoftware-jwt-auth.php')
		]);
	}

	/**
     * Get the services provided by the provider.
     *
     * @return string[]
     * @codeCoverageIgnore
     */
    public function provides()
    {
        return [
			'epsoftware.auth',
			'epsoftware.jwt'
		];
    }
}
