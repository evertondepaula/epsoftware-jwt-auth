<?php

namespace Epsoftware\Auth\Middlewares;

use Closure;
use Epsoftware\Auth\Facades\Auth;

class MiddlewareAuth
{
    public function handle($request, Closure $next)
    {
      if ( Auth::authorization($request) ) return $next( $request );

		return Auth::failResponse('Unauthorized token');
    }
}
