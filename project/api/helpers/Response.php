<?php

class Response {

    public static function json($status, $message, $data = null) {

        http_response_code($status);

        echo json_encode([
            "status"  => $status,
            "message" => $message,
            "data"    => $data
        ]);

        exit; // 🔥 important to stop execution
    }
}
