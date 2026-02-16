<?php

class RefreshToken {

    // 🔹 Create refresh token
    public static function create($userId, $hash)
    {
        $db = Database::connect();

        $expiry = date('Y-m-d H:i:s', strtotime('+7 days'));

        $stmt = $db->prepare(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at)
             VALUES (?, ?, ?, NOW())"
        );

        $stmt->bind_param("iss", $userId, $hash, $expiry);

        return $stmt->execute();
    }

    // 🔹 Delete all tokens of a user (single session policy)
    public static function deleteByUserId($userId)
    {
        $db = Database::connect();

        $stmt = $db->prepare(
            "DELETE FROM refresh_tokens WHERE user_id = ?"
        );

        $stmt->bind_param("i", $userId);

        return $stmt->execute();
    }

    // 🔹 Find valid refresh token (used in refresh endpoint)
    public static function findValidToken($refreshToken)
    {
        $db = Database::connect();

        $result = $db->query("SELECT * FROM refresh_tokens");

        while ($row = $result->fetch_assoc()) {

            if (password_verify($refreshToken, $row['token_hash'])) {
                return $row;
            }
        }

        return null;
    }

    // 🔹 Delete by refresh token (used in logout)
    public static function deleteByToken($refreshToken)
    {
        $db = Database::connect();

        $result = $db->query("SELECT * FROM refresh_tokens");

        while ($row = $result->fetch_assoc()) {

            if (password_verify($refreshToken, $row['token_hash'])) {

                $stmt = $db->prepare(
                    "DELETE FROM refresh_tokens WHERE id = ?"
                );

                $stmt->bind_param("i", $row['id']);
                return $stmt->execute();
            }
        }

        return false;
    }

}
