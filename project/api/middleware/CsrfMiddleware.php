<?php

class CsrfMiddleware {

    public static function handle()
    {
        // Only protect state-changing methods
        $method = $_SERVER['REQUEST_METHOD'];

        if (!in_array($method, ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            return;
        }

        $headers = getallheaders();
        $headerToken = $headers['X-CSRF-TOKEN'] ?? null;

        $sessionToken = $_SESSION['csrf_token'] ?? null;

        if (!$headerToken || !$sessionToken) {
            Response::json(403, "CSRF token missing");
        }

        if (!hash_equals($sessionToken, $headerToken)) {
            Response::json(403, "Invalid CSRF token");
        }
    }
}
