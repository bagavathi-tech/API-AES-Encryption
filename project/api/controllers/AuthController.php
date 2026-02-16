<?php

class AuthController {

    // ==============================
    // 🔹 REGISTER
    // ==============================
    public static function register($data)
{
    if (
        empty($data['name']) ||
        empty($data['email']) ||
        empty($data['password'])
    ) {
        Response::json(400, "All fields required");
    }

    $hashPassword = password_hash($data['password'], PASSWORD_DEFAULT);

    $created = User::create(
        $data['name'],
        $data['email'],
        $hashPassword
    );

    if (!$created) {
        Response::json(409, "Email already exists");
    }

    Response::json(201, "User registered successfully");
}


    // ==============================
    // 🔹 LOGIN
    // ==============================
    public static function login($data)
{
    if (!$data) {
        Response::json(400, "Request body missing");
    }

    if (empty($data['email']) || empty($data['password'])) {
        Response::json(400, "Email and password required");
    }

    $email = strtolower(trim($data['email']));
    $emailHash = Crypto::blindIndex($email);
    
    $user = User::findByEmailHash($emailHash);
    
    if (!$user || !password_verify($data['password'], $user['password'])) {
        Response::json(401, "Invalid credentials");
    }
    

    // 🔥 Generate Refresh Token
    $refreshToken = bin2hex(random_bytes(40));

    // 🔥 Hash refresh token for DB
    $refreshTokenHash = password_hash($refreshToken, PASSWORD_DEFAULT);

    // Save refresh token in DB (update your table accordingly)
    RefreshToken::deleteByUserId($user['id']);
    RefreshToken::create($user['id'], $refreshTokenHash);

    // 🔥 Create HMAC binding
    $binding = hash_hmac('sha256', $refreshToken, JWT_SECRET);

    // 🔥 Generate Access Token
    $accessToken = JWT::generate([
        "user_id" => $user['id'],
        "bind"    => $binding,
        "iat"     => time(),
        "exp"     => time() + JWT_EXPIRY
    ]);

    // 🔥 Store refresh token in cookie
    setcookie("refresh_token", $refreshToken, [
        "expires"  => time() + (60*60*24*7),
        "httponly" => true,
        "secure"   => false,
        "path"     => "/",
        "samesite" => "Strict"
    ]);
    // 🔥 Generate CSRF token
$csrfToken = bin2hex(random_bytes(32));

// 🔥 Store in session
$_SESSION['csrf_token'] = $csrfToken;


    $expiryTime = time() + JWT_EXPIRY;

Response::json(200, "Login success", [
    "access_token" => $accessToken,
    "expires_in"   => JWT_EXPIRY,
    "csrf_token"   => $csrfToken
]);


    
}

    // ==============================
    // 🔹 REFRESH TOKEN
    // ==============================
    public static function refresh()
{
    $refreshToken = $_COOKIE['refresh_token'] ?? null;

    if (!$refreshToken) {
        Response::json(401, "Refresh token missing");
    }

    $db = Database::connect();
    $result = $db->query("SELECT * FROM refresh_tokens");

    // ✅ If table empty
    if ($result->num_rows === 0) {
        Response::json(401, "refresh token not found ");
    }

    $validToken = null;

    while ($row = $result->fetch_assoc()) {
        if (password_verify($refreshToken, $row['token_hash'])) {
            $validToken = $row;
            break;
        }
    }

    // ✅ If rows exist but none matched
    if (!$validToken) {
        Response::json(401, "refresh token not found");
    }

    // Optional expiry check
    if (isset($validToken['expires_at']) && 
        strtotime($validToken['expires_at']) < time()) {
        Response::json(401, "Refresh token expired");
    }

    $binding = hash_hmac('sha256', $refreshToken, JWT_SECRET);

    $newAccessToken = JWT::generate([
        "user_id" => $validToken['user_id'],
        "bind"    => $binding,
        "iat"     => time(),
        "exp"     => time() + JWT_EXPIRY
    ]);

    Response::json(200, "Token refreshed", [
        "access_token" => $newAccessToken,
        "expires_in" => JWT_EXPIRY
    ]);
}




    // ==============================
    // 🔹 LOGOUT
    // ==============================
    public static function logout()
{
    // 🔹 Get refresh token from cookie
    $refreshToken = $_COOKIE['refresh_token'] ?? null;

    if ($refreshToken) {

        // 🔹 Delete refresh token from DB
        $db = Database::connect();
        $result = $db->query("SELECT * FROM refresh_tokens");

        while ($row = $result->fetch_assoc()) {
            if (password_verify($refreshToken, $row['token_hash'])) {

                $stmt = $db->prepare(
                    "DELETE FROM refresh_tokens WHERE id = ?"
                );
                $stmt->bind_param("i", $row['id']);
                $stmt->execute();
                break;
            }
        }
    }

    // 🔥 Clear all session variables
    $_SESSION = [];

    // 🔥 Destroy session
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }

    // 🔥 Remove session cookie (important)
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }

    // 🔥 Clear refresh token cookie
    setcookie("refresh_token", "", time() - 3600, "/");

    Response::json(200, "Logged out successfully");
}


}