<?php
require_once 'tiktok_api.php';

header('Content-Type: application/json');

// Token verification sebelum proses
function verifyApiToken() {
    $headers = getallheaders();
    
    // Cek token headers
    if (!isset($headers['X-Token']) || !isset($headers['X-Signature'])) {
        return ['valid' => false, 'error' => 'Token required'];
    }
    
    $token = $headers['X-Token'];
    $signature = $headers['X-Signature'];
    $sessionId = $headers['X-Session-ID'] ?? '';
    $clientOnly = isset($headers['X-Client-Only']);
    
    if ($clientOnly) {
        // Validasi client-only token
        return verifyClientToken($token, $signature, $sessionId);
    }
    
    // Validasi server token
    return verifyServerToken($token, $signature, $sessionId);
}

// Verify token
$tokenCheck = verifyApiToken();
if (!$tokenCheck['valid']) {
    http_response_code(401);
    echo json_encode(['error' => 'Token invalid', 'details' => $tokenCheck['error']]);
    exit;
}

// Lanjutkan dengan request TikTok API seperti sebelumnya
$input = json_decode(file_get_contents('php://input'), true);

// ... sisa kode TikTok API ...
