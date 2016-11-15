<?php

return [
    'auth' => [

        'providers' => [
            'model' => env('AUTH_MODEL', '\App\User'),
            'field' => env('AUTH_FIELD', 'id')
        ],

        'iss'    => env('AUTH_ISS', null),
        'sub'    => env('AUTH_SUB', null),
        'aud'    => env('AUTH_AUD', null),
        'exp'    => env('AUTH_EXP', 600),
        'nbf'    => env('AUTH_NBF', 1),
        'jti'    => env('AUTH_JTI', null),
        'secret' => env('AUTH_SECRET', 'somesecretkey')
    ]
];
