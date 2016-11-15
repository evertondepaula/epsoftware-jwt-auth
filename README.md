# epsoftware-jwt-auth
JWT LUMEN IMPLEMENTATION - BASED https://github.com/lcobucci/jwt

## Install Instructions

	1 - Uncoment in bootstrap/app.php
		- `$app->withFacades();`
		- `$app->withEloquent();`

	2 - Create Class alias in bootstrap/app.php
		 - `$app->alias('App', 'Illuminate\Support\Facades\App');`

	3 - Enable configures in bootstrap/app.php
		- `$app->configure('epsoftware-jwt-auth');`

	4 - Create file in config folder `epsoftware-jwt-auth.php`
		- ` return [
		        'providers' => [
		            'model' => env('AUTH_MODEL', '\App\User'),
		            'field' => env('AUTH_FIELD', 'id')
		        ],

				'token'  => [
					'type' => env('AUTH_TOKEN_TYPE', 'Bearer')
				],

		        'iss'    => env('AUTH_ISS', ''),
		        'sub'    => env('AUTH_SUB', ''),
		        'aud'    => env('AUTH_AUD', ''),
		        'exp'    => env('AUTH_EXP', 600),
		        'nbf'    => env('AUTH_NBF', 1),
		        'jti'    => env('AUTH_JTI', ''),
		        'secret' => env('AUTH_SECRET', 'somesecretkey')
			];
		`
	5 - Register Provider in bootstrap/app.php
		 - `$app->register(\Epsoftware\Auth\Providers\AuthServiceProvider::class);`

	6 - Register the middleware in bootstrap/app.php
		- `$app->routeMiddleware([
		   	'jwt-auth'  => \Epsoftware\Auth\Middlewares\MiddlewareAuth::class,
			]);`

		- Remember it, On midddleware alias don't use reseverd names, like `'auth'`

	7 - In `.env` make parameters `AUTH_something`
		- `AUTH_SECRET=somesecretkey`

## Use Instructions

	1 - Set middleware on Routes if you want to authenticate

		- Set middleware with yours 'alias'
			`$app->get('/route', ['middleware' => 'jwt-auth', 'uses' => 'Controller@get']);`

		- Required `Bearer Token` in Request Header Authorization

	2 - Use Facades for get user

		- `$user = \Epsoftware\Auth\Facades\Auth::getUser());` returns `User object`
		- `$user->id` 	 || '1'
		- `$user->name` || 'Tom'

	3 - Authentication user

		` if (\Epsoftware\Auth\Facades\Auth::autentication(['username' => 'value'],  $password ) ) {
			return Auth::getToken();
		}
		`
