<?php

namespace Epsoftware\Auth;

use Epsoftware\Auth\Exceptions\AuthorizationException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\JsonResponse;
use Epsoftware\Auth\Facades\JWT;
use Illuminate\Http\Request;

class Auth
{
	protected $user;
	protected $token;

	public function __construct()
	{
		$this->user = new Config::get('auth.providers.model')();
	}

	public function authentication(array $credentials, $password = null )
	{
		$user = $this->user->where($credentials)->first();

		if( $user && Hash::check( $password, $user->password) ) {
			$this->token = JWT::encode($user)->getToken();
			return true;
        } else {
			return false;
		}
	}

	public function getToken()
	{
		return $this->token;
	}

	public function authorization( Request $request )
	{
		if ( $token = $request->header('Authorization') ) {

			$token = $this->traitToken($token);

			if ( JWT::authorizer($token) ) {
				$field = JWT::getTokenUserField();
				$this->user->where([
					Config::get('auth.providers.field') => $field
				])->first();
				return true;
			}
		}

		return false;
	}

	protected function setUser( $user )
	{
		$this->user = $user;
	}

	protected function traitToken($token)
	{
		return str_replace('Bearer ', '', $token);
	}

	public function getUser()
	{
		return $this->user;
	}

	public function failResponse( $message = '', $data = null )
	{
		return new JsonResponse([
			'code'		=> 422,
			'message'	=> $message,
			'data'		=> $data
		], 422);
	}
}
