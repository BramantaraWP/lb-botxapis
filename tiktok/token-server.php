<?php
/**
 * Server-side token handler untuk verifikasi
 */

header('Content-Type: application/json');
session_start();

// Config
define('TOKEN_SECRET', 'bc1qqg0qcu5yd899676tz7lgxq3ce05jdy3m8702r0');
define('TOKEN_EXPIRY', 10800); // 3 jam dalam detik
define('ALLOWED_ORIGINS', ['https://lb-botzapi.wasmer.app']);

// CORS headers
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, ALLOWED_ORIGINS)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Headers: Content-Type, X-Session-ID");
}

// Get input
$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';

// Security check: hanya terima dari request yang valid
if (!$this->isValidRequest()) {
    http_response_code(403);
    echo json_encode(['error' => 'Invalid request']);
    exit;
}

// Handle actions
switch ($action) {
    case 'generate_token':
        echo json_encode($this->generateToken($input));
        break;
        
    case 'verify_token':
        echo json_encode($this->verifyToken($input));
        break;
        
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action']);
}

exit;

// ===== FUNCTIONS =====

function generateToken($data) {
    // Validasi fingerprint dari client
    $fingerprint = $data['fingerprint'] ?? '';
    $sessionId = $_SERVER['HTTP_X_SESSION_ID'] ?? $data['session_id'] ?? '';
    
    if (empty($fingerprint) || empty($sessionId)) {
        return ['success' => false, 'error' => 'Missing data'];
    }
    
    // Generate token payload
    $payload = [
        'session_id' => $sessionId,
        'fingerprint' => $fingerprint,
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200),
        'created' => time(),
        'expires' => time() + TOKEN_EXPIRY
    ];
    
    // Encode token
    $token = base64_encode(json_encode($payload));
    
    // Generate signature
    $signature = hash_hmac('sha256', $token, TOKEN_SECRET);
    
    // Simpan ke session untuk verifikasi nanti
    $_SESSION['api_token_' . $sessionId] = [
        'token' => $token,
        'signature' => $signature,
        'expires' => $payload['expires']
    ];
    
    // Rate limiting
    $this->trackTokenGeneration($sessionId);
    
    return [
        'success' => true,
        'token' => $token,
        'signature' => $signature,
        'expires_in' => TOKEN_EXPIRY,
        'expires_at' => $payload['expires']
    ];
}

function verifyToken($data) {
    $token = $data['token'] ?? [];
    $sessionId = $data['session_id'] ?? '';
    
    if (empty($token) || empty($sessionId)) {
        return ['valid' => false, 'error' => 'Missing token data'];
    }
    
    // Cek di session storage
    $sessionKey = 'api_token_' . $sessionId;
    
    if (!isset($_SESSION[$sessionKey])) {
        return ['valid' => false, 'error' => 'Token not found'];
    }
    
    $storedToken = $_SESSION[$sessionKey];
    
    // Cek expiry
    if (time() > $storedToken['expires']) {
        unset($_SESSION[$sessionKey]);
        return ['valid' => false, 'error' => 'Token expired'];
    }
    
    // Verify signature
    $expectedSignature = hash_hmac('sha256', $token['token'] ?? '', TOKEN_SECRET);
    
    if (!hash_equals($expectedSignature, $token['signature'] ?? '')) {
        return ['valid' => false, 'error' => 'Invalid signature'];
    }
    
    return ['valid' => true, 'message' => 'Token is valid'];
}

function isValidRequest() {
    // Cek user agent (blok curl/bot)
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    
    if (empty($ua) || strlen($ua) < 10) {
        return false;
    }
    
    $botPatterns = ['/curl/i', '/wget/i', '/python/i', '/^$/'];
    
    foreach ($botPatterns as $pattern) {
        if (preg_match($pattern, $ua)) {
            return false;
        }
    }
    
    // Cek request method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return false;
    }
    
    // Cek content type
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (strpos($contentType, 'application/json') === false) {
        return false;
    }
    
    return true;
}

function trackTokenGeneration($sessionId) {
    $key = 'token_gen_' . $sessionId;
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = [
            'count' => 1,
            'first_request' => time()
        ];
    } else {
        $_SESSION[$key]['count']++;
        
        // Max 5 token per 10 menit
        if ($_SESSION[$key]['count'] > 5 && 
            (time() - $_SESSION[$key]['first_request']) < 600) {
            http_response_code(429);
            echo json_encode(['error' => 'Too many token requests']);
            exit;
        }
        
        // Reset counter setelah 10 menit
        if ((time() - $_SESSION[$key]['first_request']) > 600) {
            $_SESSION[$key] = [
                'count' => 1,
                'first_request' => time()
            ];
        }
    }
}
?>
