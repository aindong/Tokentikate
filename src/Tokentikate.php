<?php
namespace Aindong\Tokentikate;

use Aindong\Tokentikate\Helpers;
use DomainException;
use Aindong\Tokentikate\Exceptions\SignatureInvalidException;
use Aindong\Tokentikate\Exceptions\BeforeValidException;
use Aindong\Tokentikate\Exceptions\ExpiredException;

use UnexpectedValueException;

class Tokentikate {

    protected $helper;

    /**
     * List of supported hashing algorithms
     *
     * @var array
     */
    protected $supported_algs = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'RS256' => ['openssl', 'SHA256']
    ];

    public function __construct(Helpers $helper)
    {
        $this->helper = $helper;
    }

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string      $jwt           The JWT
     * @param string|Array|null $key     The secret key, or map of keys
     * @param Array       $allowed_algs  List of supported verification algorithms
     *
     * @return object      The JWT's payload as a PHP object
     *
     * @throws DomainException              Algorithm was not provided
     * @throws UnexpectedValueException     Provided JWT was invalid
     * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     * @throws BeforeValidException         Provided JWT is trying to be used before it's eligible as defined by 'nbf'
     * @throws BeforeValidException         Provided JWT is trying to be used before it's been created as defined by 'iat'
     * @throws ExpiredException             Provided JWT has since expired, as defined by the 'exp' claim
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public function decode($jwt, $key = null, $allowed_algs = array())
    {
        $tks = explode('.', $jwt);

        if (count($tks) != 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($headb64, $bodyb64, $cryptob64) = $tks;

        if (null === ($header = $this->helper->jsonDecode($this->helper->urlsafeB64Decode($headb64)))) {
            throw new UnexpectedValueException('Invalid header encoding');
        }

        if (null === $payload = $this->helper->jsonDecode($this->helper->urlsafeB64Decode($bodyb64))) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }

        $sig = $this->helper->urlsafeB64Decode($cryptob64);

        if (isset($key)) {

            if (empty($header->alg)) {
                throw new DomainException('Empty algorithm');
            }

            if (empty($this->supported_algs[$header->alg])) {
                throw new DomainException('Algorithm not supported');
            }

            if (!is_array($allowed_algs) || !in_array($header->alg, $allowed_algs)) {
                throw new DomainException('Algorithm not allowed');
            }

            if (is_array($key)) {
                if (isset($header->kid)) {
                    $key = $key[$header->kid];
                } else {
                    throw new DomainException('"kid" empty, unable to lookup correct key');
                }
            }

            // Check the signature
            if (!$this->verify("$headb64.$bodyb64", $sig, $key, $header->alg)) {
                throw new SignatureInvalidException('Signature verification failed');
            }

            // Check if the nbf if it is defined. This is the time that the
            // token can actually be used. If it's not yet that time, abort.
            if (isset($payload->nbf) && $payload->nbf > time()) {
                throw new BeforeValidException(
                    'Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload->nbf)
                );
            }

            // Check that this token has been created before 'now'. This prevents
            // using tokens that have been created for later use (and haven't
            // correctly used the nbf claim).
            if (isset($payload->iat) && $payload->iat > time()) {
                throw new BeforeValidException(
                    'Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload->iat)
                );
            }

            // Check if this token has expired.
            if (isset($payload->exp) && time() >= $payload->exp) {
                throw new ExpiredException('Expired token');
            }
        }

        return $payload;
    }


    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param object|array $payload PHP object or array
     * @param string       $key     The secret key
     * @param string       $alg     The signing algorithm. Supported
     *                              algorithms are 'HS256', 'HS384' and 'HS512'
     *
     * @return string      A signed JWT
     * @uses jsonEncode
     * @uses urlsafeB64Encode
     */
    public function encode($payload, $key, $alg = 'HS256', $keyId = null)
    {
        $header = array('typ' => 'JWT', 'alg' => $alg);

        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }

        $segments = array();
        $segments[] = $this->helper->urlsafeB64Encode($this->helper->jsonEncode($header));
        $segments[] = $this->helper->urlsafeB64Encode($this->helper->jsonEncode($payload));
        $signing_input = implode('.', $segments);
        $signature = $this->sign($signing_input, $key, $alg);
        $segments[] = $this->helper->urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string $msg          The message to sign
     * @param string|resource $key The secret key
     * @param string $alg       The signing algorithm. Supported algorithms
     *                               are 'HS256', 'HS384', 'HS512' and 'RS256'
     *
     * @return string          An encrypted message
     * @throws DomainException Unsupported algorithm was specified
     */
    private function sign($msg, $key, $alg = 'HS256')
    {
        if (empty($this->supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }

        list($function, $algorithm) = $this->supported_algs[$alg];

        switch($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $msg, $key, true);
            case 'openssl':
                $signature = '';
                $success = openssl_sign($msg, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL unable to sign data");
                } else {
                    return $signature;
                }
            default:
                return hash_hmac($algorithm, $msg, $key, true);
        }
    }

    /**
     * Verify a signature with the mesage, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string $msg the original message
     * @param string $signature
     * @param string|resource $key for HS*, a string key works. for RS*, must be a resource of an openssl public key
     * @param string $alg
     * @return bool
     * @throws DomainException Invalid Algorithm or OpenSSL failure
     */
    private function verify($msg, $signature, $key, $alg)
    {
        if (empty($this->supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }

        list($function, $algorithm) = $this->supported_algs[$alg];

        switch($function) {
            case 'openssl':
                $success = openssl_verify($msg, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL unable to verify data: " . openssl_error_string());
                } else {
                    return $signature;
                }
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $msg, $key, true);
                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }
                $len = min($this->helper->safeStrlen($signature), $this->helper->safeStrlen($hash));
                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (ord($signature[$i]) ^ ord($hash[$i]));
                }
                $status |= ($this->helper->safeStrlen($signature) ^ $this->helper->safeStrlen($hash));
                return ($status === 0);
        }
    }
}