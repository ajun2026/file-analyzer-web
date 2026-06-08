<?php
/**
 * 聊天记录持久化 API
 * GET  ?action=load&id=xxx   → 加载聊天记录
 * POST ?action=save           → 保存聊天记录 {id, messages}
 * POST ?action=clear&id=xxx   → 清除聊天记录
 */
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';

require_once __DIR__ . '/config.php';
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($mysqli->connect_error) {
    echo json_encode(['error' => '数据库连接失败']);
    exit;
}
$mysqli->set_charset('utf8mb4');

// ── 加载聊天记录 ──
if ($action === 'load') {
    $id = $_GET['id'] ?? '';
    if (!$id) {
        echo json_encode(['error' => '缺少 id 参数']);
        exit;
    }
    $sessionId = basename($id);  // 安全：只取文件名部分
    $stmt = $mysqli->prepare('SELECT messages FROM chat_history WHERE session_id = ?');
    $stmt->bind_param('s', $sessionId);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    if ($row) {
        echo $row['messages'];  // 已经是 JSON
    } else {
        echo json_encode(['messages' => []]);
    }
    $stmt->close();
}

// ── 保存聊天记录 ──
elseif ($action === 'save') {
    $input = json_decode(file_get_contents('php://input'), true);
    $id = $input['id'] ?? '';
    $messages = $input['messages'] ?? [];
    if (!$id) {
        echo json_encode(['error' => '缺少 id 参数']);
        exit;
    }
    $sessionId = basename($id);
    $json = json_encode(['messages' => $messages], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    
    $stmt = $mysqli->prepare(
        'INSERT INTO chat_history (session_id, messages) VALUES (?, ?) 
         ON DUPLICATE KEY UPDATE messages = VALUES(messages)'
    );
    $stmt->bind_param('ss', $sessionId, $json);
    $success = $stmt->execute();
    echo json_encode(['success' => $success]);
    $stmt->close();
}

// ── 清除聊天记录 ──
elseif ($action === 'clear') {
    $id = $_GET['id'] ?? '';
    if (!$id) {
        echo json_encode(['error' => '缺少 id 参数']);
        exit;
    }
    $sessionId = basename($id);
    $stmt = $mysqli->prepare('DELETE FROM chat_history WHERE session_id = ?');
    $stmt->bind_param('s', $sessionId);
    $success = $stmt->execute();
    echo json_encode(['success' => $success]);
    $stmt->close();
}

else {
    echo json_encode(['error' => '未知操作，支持: load, save, clear']);
}

$mysqli->close();
