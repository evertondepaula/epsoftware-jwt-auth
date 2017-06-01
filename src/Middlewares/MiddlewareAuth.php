<?php

namespace Epsoftware\Auth\Middlewares;

use Closure;
use Epsoftware\Auth\Exceptions\AuthorizationException;
use Epsoftware\Auth\Facades\Auth;

class MiddlewareAuth
{
    public function handle($request, Closure $next)
    {
      if ( Auth::authorization($request) ) return $next( $request );

        throw new AuthorizationException('Unauthorized token', 401);
    }
}
