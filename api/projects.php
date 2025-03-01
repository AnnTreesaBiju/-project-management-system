<?php
header('Content-Type: application/json');
require_once '../config/db.php';
require_once '../libs/jwt.php';

$method = $_SERVER['REQUEST_METHOD'];
$token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$userId = verifyJWT(str_replace('Bearer ', '', $token));

if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$conn = getDBConnection();
$data = json_decode(file_get_contents('php://input'), true);

switch ($method) {
    case 'POST': // Create
        $name = $data['name'];
        $stmt = $conn->prepare("INSERT INTO projects (user_id, name) VALUES (?, ?)");
        $stmt->execute([$userId, $name]);
        echo json_encode(['message' => 'Project created', 'id' => $conn->lastInsertId()]);
        break;

    case 'PUT': // Update
        $id = $data['id'];
        $name = $data['name'];
        $stmt = $conn->prepare("UPDATE projects SET name = ? WHERE id = ? AND user_id = ?");
        $stmt->execute([$name, $id, $userId]);
        echo json_encode(['message' => 'Project updated']);
        break;

    case 'DELETE': // Delete
        $id = $data['id'];
        $stmt = $conn->prepare("DELETE FROM projects WHERE id = ? AND user_id = ?");
        $stmt->execute([$id, $userId]);
        echo json_encode(['message' => 'Project deleted']);
        break;

    case 'GET': // List
        $stmt = $conn->prepare("SELECT * FROM projects WHERE user_id = ?");
        $stmt->execute([$userId]);
        $projects = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode($projects);
        break;
}
?>