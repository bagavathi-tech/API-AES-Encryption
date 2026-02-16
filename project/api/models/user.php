<?php
class User {

    public static function findByEmailHash($hash)
    {
        $db = Database::connect();

        $stmt = $db->prepare(
            "SELECT * FROM users WHERE email_hash = ? LIMIT 1"
        );

        $stmt->bind_param("s", $hash);
        $stmt->execute();

        return $stmt->get_result()->fetch_assoc();
    }

    public static function create($name, $emailRaw, $password)
    {
        $db = Database::connect();

        $emailEncrypted = Crypto::encrypt($emailRaw);
        $emailHash      = Crypto::blindIndex($emailRaw);

        // Duplicate check
        if (self::findByEmailHash($emailHash)) {
            return false;
        }

        $stmt = $db->prepare(
            "INSERT INTO users (name, email, email_hash, password)
             VALUES (?, ?, ?, ?)"
        );

        $stmt->bind_param(
            "ssss",
            $name,
            $emailEncrypted,
            $emailHash,
            $password
        );

        return $stmt->execute();
    }


    // 🔽 ===== ADDITIONAL METHODS (refresh token) =====

    public static function updateRefreshToken($userId, $token) {
        $db = Database::connect();

        $stmt = $db->prepare(
            "UPDATE users SET refresh_token = ? WHERE id = ?"
        );
        $stmt->bind_param("si", $token, $userId);

        return $stmt->execute();
    }

    public static function findByRefreshToken($token) {
        $db = Database::connect();

        $stmt = $db->prepare(
            "SELECT * FROM users WHERE refresh_token = ?"
        );
        $stmt->bind_param("s", $token);
        $stmt->execute();

        return $stmt->get_result()->fetch_assoc();
    }

    public static function clearRefreshToken($token) {
        $db = Database::connect();

        $stmt = $db->prepare(
            "UPDATE users SET refresh_token = NULL WHERE refresh_token = ?"
        );
        $stmt->bind_param("s", $token);

        return $stmt->execute();
    }

} 
