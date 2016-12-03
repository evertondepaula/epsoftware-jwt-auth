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
	protected $tokenType;

	public function __construct()
	{
		$userClass = Config::get('epsoftware-jwt-auth.providers.model');
		$this->tokenType = Config::get('epsoftware-jwt-auth.token.type');
		$this->user = new $userClass();
	}

	public function authentication( array $credentials, $password = null )
	{
		$user = $this->user->where($credentials)->first();

		if( $user && Hash::check( $password['password'], $user->password) ) {
			$this->token = JWT::encode($user)->getToken();
			$this->user = $user;
			return true;
        } else {
			return false;
		}
	}

	public function getToken()
	{
		return sprintf("%s", $this->token);
	}

	public function authorization( Request $request )
	{
		if ( $this->token = $request->header('Authorization') ) {

			$this->token = $this->traitToken($this->token);

			if ( JWT::authorizer($this->token) ) {
				$field = JWT::getTokenUserField();
				$user = $this->user->where([
					Config::get('epsoftware-jwt-auth.providers.field') => $field
				])->first();
				$this->user = $user;
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
		return str_replace($this->tokenType, '', $token);
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
