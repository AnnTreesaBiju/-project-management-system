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
        $projectId = $data['project_id'];
        $title = $data['title'];
        $stmt = $conn->prepare("INSERT INTO tasks (project_id, title) VALUES (?, ?)");
        $stmt->execute([$projectId, $title]);
        echo json_encode(['message' => 'Task created', 'id' => $conn->lastInsertId()]);
        break;

    case 'PUT': // Update Task or Status
        $taskId = $data['id'];
        if (isset($data['title'])) {
            $title = $data['title'];
            $stmt = $conn->prepare("UPDATE tasks SET title = ? WHERE id = ? AND project_id IN (SELECT id FROM projects WHERE user_id = ?)");
            $stmt->execute([$title, $taskId, $userId]);
            echo json_encode(['message' => 'Task updated']);
        }
        if (isset($data['status'])) {
            $status = $data['status'];
            $remarks = $data['remarks'] ?? '';
            $stmt = $conn->prepare("UPDATE tasks SET status = ? WHERE id = ? AND project_id IN (SELECT id FROM projects WHERE user_id = ?)");
            $stmt->execute([$status, $taskId, $userId]);
            $stmt = $conn->prepare("INSERT INTO task_status_history (task_id, status, remarks) VALUES (?, ?, ?)");
            $stmt->execute([$taskId, $status, $remarks]);
            echo json_encode(['message' => 'Task status updated']);
        }
        break;

    case 'DELETE': // Delete
        $taskId = $data['id'];
        $stmt = $conn->prepare("DELETE FROM tasks WHERE id = ? AND project_id IN (SELECT id FROM projects WHERE user_id = ?)");
        $stmt->execute([$taskId, $userId]);
        echo json_encode(['message' => 'Task deleted']);
        break;

    case 'GET': // List tasks for a project
        $projectId = $_GET['project_id'];
        $stmt = $conn->prepare("SELECT * FROM tasks WHERE project_id = ? AND project_id IN (SELECT id FROM projects WHERE user_id = ?)");
        $stmt->execute([$projectId, $userId]);
        $tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode($tasks);
        break;
}
?>