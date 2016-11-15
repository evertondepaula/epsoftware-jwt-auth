<?php

namespace Epsoftware\Auth;

use Epsoftware\Auth\Exceptions\AuthenticationException;
use Illuminate\Support\Facades\Config;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Configuration;
use DateInterval;
use DateTime;

class JWT
{
    protected $ISS;
    protected $SUB;
    protected $AUD;
    protected $EXP;
    protected $NBF;
    protected $IAT;
    protected $JTI;
    protected $SECRET;
    protected $TOKEN;
    protected $FIELD;

    public function __construct() {

        $iat = new DateTime();
        $minutesToExp = Config::get('auth.exp');
        $validadeStart = Config::get('auth.nbf');

        $exp = $iat->add(new DateInterval("PT{$minutesToExp}M"));
        $nbf = $iat->add(new DateInterval("PT{$validadeStart}S"));

        $this->IAT = $iat->getTimestamp();
        $this->EXP = $exp->getTimestamp();
        $this->NBF = $nbf->getTimestamp();
        $this->SECRET = Config::get('auth.secret');
        $this->ISS = Config::get('auth.iss');
        $this->SUB = Config::get('auth.sub');
        $this->AUD = Config::get('auth.aud');
        $this->JTI = Config::get('auth.jti');
        $this->FIELD = Config::get('auth.providers.field');

        return $this;
    }

    public function decode( $tokenString )
    {
        try {
            $config = new Configuration();
            //Parses from a string
            $this->TOKEN =  $config->getParser()->parse((string) $tokenString);
        } catch (AuthenticationException $e) {
            throw new AuthenticationException("Decode token error", 404);
        }
    }

    public function encode( $user )
    {
        //This object helps to simplify the creation of the dependencies
        $config = new Configuration();
        //Default signer is HMAC SHA256
        $signer = $config->getSigner();
        $this->TOKEN = $config->createBuilder()
                // Configures the issuer (iss claim)
                ->issuedBy($this->ISS)
                //Configures the audience (aud claim)
                ->canOnlyBeUsedBy($this->AUD)
                //Configures the id (jti claim), replicating as a header item
                ->identifiedBy($this->JTI, true)
                //Configures the time that the token was issue (iat claim)
                ->issuedAt($this->IAT)
                //Configures the time that the token can be used (nbf claim)
                ->canOnlyBeUsedAfter($this->NBF)
                //Configures the expiration time of the token (exp claim)
                ->expiresAt($this->EXP)
                //Configures a new claim, called "uid"
                ->with($this->FIELD, $user->{$this->FIELD})
                //Creates a signature using "testing" as key
                ->sign($signer, $this->SECRET)
                //Retrieves the generated token
                ->getToken();
    }

    public function validate( $token )
    {
        try {
            //It will use the current time to validate (iat, nbf and exp)
            $data = new ValidationData();
            $data->setIssuer($this->ISS);
            $data->setAudience($this->AUD);
            $data->setId($this->JTI);

            return $this->TOKEN->validate($data);

        } catch (AuthenticationException $e) {
            throw new AuthenticationException("Validation token error", 404);
        }
    }

    public function sing( )
    {
        try {
            // This object helps to simplify the creation of the dependencies
            $config = new Configuration();
            // Default signer is HMAC SHA256
            $signer = $config->getSigner();
            return $this->TOKEN->verify($signer, $this->SECRET);

        } catch (AuthenticationException $e) {
            throw new AuthenticationException("Sing token error", 404);
        }
    }

    public function authorizer( $tokenString )
    {
        try {
            $this->decode($tokenString);
            if ( $this->sing() && $this->validate() ) return true;
            return false;
        } catch (AuthenticationException $e) {
            throw new AuthenticationException("Authorizer error", 404);
        }
    }

    public function getToken()
    {
        return $this->TOKEN;
    }

    public function getTokenUserField()
    {
        return $this->TOKEN->getClaim($this->FIELD);
    }
}
