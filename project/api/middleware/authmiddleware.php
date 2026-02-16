<?php
class AuthMiddleware {

    public static function handle()
    {
        $headers = getallheaders();

        if (!isset($headers['Authorization'])) {
            Response::json(401, "Authorization token missing");
        }

        $token = str_replace("Bearer ", "", $headers['Authorization']);
        $payload = JWT::verify($token);

        if (!$payload) {
            Response::json(401, "Invalid or expired token");
        }

        // 🔥 Get refresh token from cookie
        $refreshToken = $_COOKIE['refresh_token'] ?? null;

        if (!$refreshToken) {
            Response::json(401, "Refresh token missing");
        }

        // 🔥 NEW: Check DB to see if session still valid
        $validToken = RefreshToken::findValidToken($refreshToken);

        if (!$validToken) {
            Response::json(401, "Session revoked");
        }

        // 🔥 Recalculate binding
        $expectedBind = hash_hmac('sha256', $refreshToken, JWT_SECRET);

        if ($payload['bind'] !== $expectedBind) {
            Response::json(401, "Token mismatch - Unauthorized");
        }

        return $payload;
    }
}
