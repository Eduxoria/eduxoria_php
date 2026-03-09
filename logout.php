<?php
// logout.php
// Destroys the student session and redirects to login

define('ALLOWED_ENTRY_POINT', true);
session_start();

// Clear all session data
$_SESSION = [];

// Destroy the session cookie
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

// Completely destroy the session
session_destroy();

// Optional: clear any other auth-related cookies if you use them
// setcookie('some_remember_token', '', time() - 3600, '/');

// Redirect to login page
header("Location: login.php");
exit;
?>