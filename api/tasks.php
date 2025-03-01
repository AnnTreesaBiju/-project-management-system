<?php
header('Content-Type: application/json');
require_once '../config/db.php';
require_once '../libs/jwt.php';

$method = $_SERVER['REQUEST_METHOD'];

// Retrieve JWT Token from Headers
$headers = getallheaders();
$token = $headers['Authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$userId = verifyJWT(str_replace('Bearer ', '', $token));

// Debug: Log if no token is received
if (!$token) {
    error_log("No token received");
}

// Authorization Check
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// Establish Database Connection
$conn = getDBConnection();
$data = json_decode(file_get_contents('php://input'), true);

/**
 * Validate if the project exists and belongs to the user.
 */
function isValidProject($conn, $projectId, $userId) {
    $stmt = $conn->prepare("SELECT id FROM projects WHERE id = ? AND user_id = ? LIMIT 1");
    $stmt->execute([$projectId, $userId]);
    $project = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$project) {
        error_log("Project not found or not owned: Project ID = $projectId, User ID = $userId");
    }

    return $project !== false;
}

switch ($method) {
    case 'POST': // Create Task
        $projectId = $data['project_id'];
        $title = $data['title'];

        // Check if project belongs to user
        if (!isValidProject($conn, $projectId, $userId)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid project ID or permission denied']);
            exit;
        }

        $stmt = $conn->prepare("INSERT INTO tasks (project_id, title, status) VALUES (?, ?, 'Pending')");
        $stmt->execute([$projectId, $title]);

        echo json_encode(['message' => 'Task created', 'id' => $conn->lastInsertId()]);
        break;

    case 'PUT': // Update Task
        $taskId = $data['id'];
        $title = $data['title'] ?? null;
        $status = $data['status'] ?? null;
        $remarks = $data['remarks'] ?? '';

        // Validate task ownership before updating
        $stmt = $conn->prepare("SELECT project_id FROM tasks WHERE id = ?");
        $stmt->execute([$taskId]);
        $task = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$task || !isValidProject($conn, $task['project_id'], $userId)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid task ID or permission denied']);
            exit;
        }

        // Update task title
        if ($title) {
            $stmt = $conn->prepare("UPDATE tasks SET title = ? WHERE id = ?");
            $stmt->execute([$title, $taskId]);
        }

        // Update task status
        if ($status) {
            $stmt = $conn->prepare("UPDATE tasks SET status = ? WHERE id = ?");
            $stmt->execute([$status, $taskId]);

            // Log status change in history
            $stmt = $conn->prepare("INSERT INTO task_status_history (task_id, status, remarks) VALUES (?, ?, ?)");
            $stmt->execute([$taskId, $status, $remarks]);
        }

        echo json_encode(['message' => 'Task updated']);
        break;

    case 'DELETE': // Delete Task
        $taskId = $data['id'];

        // Validate task ownership before deleting
        $stmt = $conn->prepare("SELECT project_id FROM tasks WHERE id = ?");
        $stmt->execute([$taskId]);
        $task = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$task || !isValidProject($conn, $task['project_id'], $userId)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid task ID or permission denied']);
            exit;
        }

        $stmt = $conn->prepare("DELETE FROM tasks WHERE id = ?");
        $stmt->execute([$taskId]);

        echo json_encode(['message' => 'Task deleted']);
        break;

    case 'GET': // List Tasks
        $projectId = $_GET['project_id'];

        // Validate project ownership before fetching tasks
        if (!isValidProject($conn, $projectId, $userId)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid project ID or permission denied']);
            exit;
        }

        $stmt = $conn->prepare("SELECT * FROM tasks WHERE project_id = ?");
        $stmt->execute([$projectId]);
        $tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode($tasks);
        break;

    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method Not Allowed']);
}
?>
