<?php
class JsonMiddleware {

    public static function handle() {

        // CORS
        header("Content-Type: application/json");
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
        header("Access-Control-Allow-Headers: Content-Type, Authorization");

        // Preflight
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit;
        }

        if (in_array($_SERVER['REQUEST_METHOD'], ['POST','PUT','PATCH'])) {

            $contentType =
                $_SERVER['CONTENT_TYPE']
                ?? $_SERVER['HTTP_CONTENT_TYPE']
                ?? '';

            if (stripos($contentType, 'application/json') === false) {
                Response::json(400, "Content-Type must be application/json");
            }

            $raw = file_get_contents("php://input");

            if (!$raw) {
                Response::json(400, "Request body required");
            }

            $data = json_decode($raw, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                Response::json(400, "Invalid JSON payload");
            }

            return $data; 
        }

        return [];
    }
}
