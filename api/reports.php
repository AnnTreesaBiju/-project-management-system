<?php
header('Content-Type: application/json');
require_once '../config/db.php';
require_once '../libs/jwt.php';

$method = $_SERVER['REQUEST_METHOD'];

// Enhanced token retrieval
$headers = getallheaders(); // More reliable than $_SERVER for some setups
$token = $headers['Authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$userId = verifyJWT(str_replace('Bearer ', '', $token));

// Debug (optional, remove in production)
if (!$token) {
    file_put_contents('debug.log', "No token received\n", FILE_APPEND);
}

// Authorization check
if (!$userId) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$conn = getDBConnection();
$projectId = $_GET['project_id'];

$stmt = $conn->prepare("
    SELECT t.id, t.title, t.status, t.created_at, 
           GROUP_CONCAT(JSON_OBJECT('status', h.status, 'remarks', h.remarks, 'updated_at', h.updated_at)) as history
    FROM tasks t
    LEFT JOIN task_status_history h ON t.id = h.task_id
    WHERE t.project_id = ? AND t.project_id IN (SELECT id FROM projects WHERE user_id = ?)
    GROUP BY t.id
");
$stmt->execute([$projectId, $userId]);
$report = $stmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($report as &$row) {
    $row['history'] = json_decode('[' . $row['history'] . ']', true);
}
echo json_encode($report);
?>