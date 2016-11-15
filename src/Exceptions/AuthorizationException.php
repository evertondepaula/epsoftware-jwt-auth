<?php

namespace Epsoftware\Auth\Exceptions;

use Exception;

/**
 * Define uma classe de exceção
 */
class AuthorizationException extends Exception
{
    public function __construct($message, $code = 0, Exception $previous = null)
    {
        // garante que tudo está corretamente inicializado
        parent::__construct($message, $code, $previous);
    }

    // personaliza a apresentação do objeto como string
    public function __toString() {
        return __CLASS__ . ": [{$this->code}]: {$this->message}\nIn File: {$this->file}, on Line: {$this->line}\n";
    }

}
