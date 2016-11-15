<?php

return [
    'providers' => [
        'model' => env('AUTH_MODEL', '\App\Models\User\User'),
        'field' => env('AUTH_FIELD', 'uuid')
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
