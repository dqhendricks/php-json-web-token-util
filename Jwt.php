<?
    class Jwt {
        protected $secret;
        protected $issuer;
        protected $audience;
        protected $tokenDuration;

        function __construct($secret, $issuer, $audience, $tokenDuration = 1 * 60 * 60) {
            $this->secret = $secret;
            $this->issuer = $issuer;
            $this->audience = $audience;
            $this->tokenDuration = $tokenDuration;
        }

        // payload overrides defaults
        public function createToken($payload) {
            $header = $this->encodeTokenObject(['typ' => 'JWT', 'alg' => 'HS256']);
            $payload = array_merge(['iss' => $this->issuer, 'aud' => $this->audience, 'iat' => time(), 'exp' => time() + $this->tokenDuration], $payload);
            $payload = $this->encodeTokenObject($payload);
            $signature = $this->base64UrlEncode(hash_hmac('sha256', $header . '.' . $payload, $this->secret, true));
            return $header . '.' . $payload . '.' . $signature;
        }

        // returns false if token is invalid
        public function getTokenPayload($token) {
            [$header, $payload, $signature] = explode('.', $token);

            // validate
            if (!$this->isValidSignature($header, $payload, $signature)) return false;
            $header = $this->decodeTokenObject($header);
            if ($header['typ'] !== 'JWT' || $header['alg'] !== 'HS256') return false;
            $payload = $this->decodeTokenObject($payload);
            if ($payload['iss'] !== $this->issuer || $payload['aud'] !== $this->audience || $payload['exp'] < time()) return false;
            
            return $payload;
        }

        private function encodeTokenObject($input) {
            return $this->base64UrlEncode(json_encode($input));
        }

        private function base64UrlEncode($input) {
            return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($input));
        }

        private function decodeTokenObject($input) {
            return (array)json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $input)));
        }

        private function isValidSignature($header, $payload, $signature) {
            return ($this->decodeTokenObject($signature) !== hash_hmac('sha256', $header . '.' . $payload, $this->secret, true));
        }
    }
?>
