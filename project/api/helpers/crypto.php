<?php
class Crypto {

    private static function key()
    {
        return hash('sha256', AES_SECRET, true); // 32 bytes
    }

    public static function encrypt($plainText)
    {
        $key = self::key();
        $iv  = random_bytes(16);

        $cipher = openssl_encrypt(
            $plainText,
            'AES-256-CBC',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        return base64_encode($iv . $cipher);
    }

    public static function decrypt($encrypted)
    {
        $key = self::key();
        $decoded = base64_decode($encrypted, true);

        if ($decoded === false || strlen($decoded) < 16) {
            return null;
        }

        $iv = substr($decoded, 0, 16);
        $cipher = substr($decoded, 16);

        return openssl_decrypt(
            $cipher,
            'AES-256-CBC',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
    }

    public static function blindIndex($value)
    {
        return hash_hmac(
            'sha256',
            strtolower(trim($value)),
            HASH_SECRET
        );
    }
}
