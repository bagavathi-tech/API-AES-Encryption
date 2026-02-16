<?php
session_start();


// ===============================
// ERROR REPORTING (DEV ONLY)
// ===============================
error_reporting(E_ALL);
ini_set('display_errors', 1);

// ===============================
// CONFIG
// ===============================
require_once __DIR__ . '/../config/config.php';

// ===============================
// HELPERS
// ===============================
require_once __DIR__ . '/../api/helpers/response.php';
require_once __DIR__ . '/../api/helpers/jwt.php';
require_once __DIR__ . '/../api/helpers/Crypto.php';


// ===============================
// CORE
// ===============================
require_once __DIR__ . '/../api/core/database.php';
require_once __DIR__ . '/../api/core/router.php';

// ===============================
// MIDDLEWARE
// ===============================
require_once __DIR__ . '/../api/middleware/JsonMiddleware.php';
require_once __DIR__ . '/../api/middleware/AuthMiddleware.php';
require_once '../api/middleware/CsrfMiddleware.php';


// ===============================
// MODELS
// (⚠️ filenames must match exactly)
// ===============================
require_once __DIR__ . '/../api/models/user.php';
require_once '../api/models/RefreshToken.php';
require_once __DIR__ . '/../api/models/patients.php';

// ===============================
// CONTROLLERS
// ===============================
require_once __DIR__ . '/../api/controllers/AuthController.php';
require_once __DIR__ . '/../api/controllers/PatientController.php';

// ===============================
// JSON + CORS + BODY HANDLING
// ===============================
$body = JsonMiddleware::handle();

// ===============================
// URI NORMALIZATION
// ===============================
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);


$basePath = '/project';

if (strpos($uri, $basePath) === 0) {
    $uri = substr($uri, strlen($basePath));
}

// default root fix
if ($uri === '') {
    $uri = '/';
}

// ===============================
$method = $_SERVER['REQUEST_METHOD'];

// ===============================
// ROUTE REQUEST
// ===============================
Router::route($uri, $method, $body);