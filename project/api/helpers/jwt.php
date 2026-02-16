<?php
class JWT {

    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public static function generate($payload) {
        $header = [
            "alg" => "HS256",
            "typ" => "JWT"
        ];

        $headerEncoded  = self::base64UrlEncode(json_encode($header));
        $payloadEncoded = self::base64UrlEncode(json_encode($payload));

        $signature = self::base64UrlEncode(hash_hmac(
            "sha256",
            "$headerEncoded.$payloadEncoded",
            JWT_SECRET
        ));

        return "$headerEncoded.$payloadEncoded.$signature";
    }

    public static function verify($token) {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false; // Invalid token structure
        }

        $header = json_decode(self::base64UrlDecode($parts[0]), true);
        $payload = json_decode(self::base64UrlDecode($parts[1]), true);
        $signature = $parts[2];

        if (!$header || !$payload) {
            return false; // Invalid JSON
        }

        // Verify signature
        $expectedSignature = self::base64UrlEncode(hash_hmac(
            "sha256",
            "$parts[0].$parts[1]",
            JWT_SECRET
        ));

        if (!hash_equals($expectedSignature, $signature)) {
            return false; // Bad signature
        }

        // Check expiry
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return false; // Expired
        }

        return $payload; // Return payload if valid
    }
}