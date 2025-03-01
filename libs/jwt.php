<?php
function generateJWT($userId) {
    $secret = 'C5B1AAD6663585A782C7A6A64C82B';
    $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = base64_encode(json_encode([
        'user_id' => $userId,
        'iat' => time(),
        'exp' => time() + 3600 // 1 hour expiry
    ]));
    $signature = hash_hmac('sha256', "$header.$payload", $secret, true);
    $signature = base64_encode($signature);
    return "$header.$payload.$signature";
}

function verifyJWT($token) {
    $secret = 'C5B1AAD6663585A782C7A6A64C82B';
    list($header, $payload, $signature) = explode('.', $token);
    $expectedSignature = hash_hmac('sha256', "$header.$payload", $secret, true);
    $expectedSignature = base64_encode($expectedSignature);
    if ($signature !== $expectedSignature) return false;

    $payload = json_decode(base64_decode($payload), true);
    if ($payload['exp'] < time()) return false;
    return $payload['user_id'];
}
?>