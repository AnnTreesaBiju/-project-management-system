<?php
header('Content-Type: application/json');
require_once '../config/db.php';
require_once '../libs/jwt.php';

$method = $_SERVER['REQUEST_METHOD'];
$data = json_decode(file_get_contents('php://input'), true);

if ($method === 'POST') {
    $conn = getDBConnection();

    if (isset($data['register'])) {
        // Register
        $email = $data['email'];
        $password = password_hash($data['password'], PASSWORD_BCRYPT);

        $stmt = $conn->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
        $stmt->execute([$email, $password]);
        echo json_encode(['message' => 'User registered']);
    } elseif (isset($data['login'])) {
        // Login
        $email = $data['email'];
        $password = $data['password'];

        $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $token = generateJWT($user['id']);
            echo json_encode(['token' => $token]);
        } else {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid credentials']);
        }
    }
}
?>