<?php
/**
 * API GATEWAY UNTUK TIKTOK ZEFAME
 * Full version dengan token verification & security
 */

// ===== CONFIGURATION =====
define('ZEFAME_API_URL', 'https://zefame-free.com/api_free.php');
define('TIKTOK_VIEWS_SERVICE_ID', 229);
define('TIKTOK_LIKES_SERVICE_ID', 232);
define('API_SECRET_KEY', 'bc1qqg0qcu5yd899676tz7lgxq3ce05jdy3m8702r0!');
define('TOKEN_EXPIRY', 10800); // 3 jam
define('MAX_REQUESTS_PER_MIN', 30);
define('ALLOWED_ORIGINS', ['https://lb-botzapi.wasmer.app', 'http://localhost']);

// Start session untuk rate limiting
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ===== HEADERS & CORS =====
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// Handle CORS
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, ALLOWED_ORIGINS)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    header("Access-Control-Allow-Headers: Content-Type, X-Token, X-Signature, X-Session-ID, X-Client-Only");
    header("Access-Control-Allow-Methods: POST, OPTIONS");
}

// Handle preflight request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// ===== MAIN API HANDLER =====
try {
    // Validasi request method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Only POST method allowed', 405);
    }
    
    // Validasi content type
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (stripos($contentType, 'application/json') === false) {
        throw new Exception('Content-Type must be application/json', 400);
    }
    
    // Get request body
    $input = json_decode(file_get_contents('php://input'), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON data', 400);
    }
    
    // ===== STEP 1: TOKEN VERIFICATION =====
    $tokenResult = verifyApiToken();
    if (!$tokenResult['valid']) {
        http_response_code(401);
        echo json_encode([
            'success' => false,
            'error' => 'Authentication failed',
            'message' => $tokenResult['error']
        ]);
        exit;
    }
    
    // ===== STEP 2: VALIDATE INPUT =====
    if (!isset($input['video_url']) || empty($input['video_url'])) {
        throw new Exception('video_url is required', 400);
    }
    
    $videoUrl = trim($input['video_url']);
    $action = isset($input['action']) ? strtolower($input['action']) : 'views';
    $quantity = isset($input['quantity']) ? intval($input['quantity']) : 100;
    
    // Validate action
    if (!in_array($action, ['views', 'likes'])) {
        throw new Exception('action must be "views" or "likes"', 400);
    }
    
    // Validate quantity
    if ($quantity < 1 || $quantity > 10000) {
        throw new Exception('quantity must be between 1 and 10000', 400);
    }
    
    // Validate TikTok URL
    if (!isValidTikTokUrl($videoUrl)) {
        throw new Exception('Invalid TikTok URL format', 400);
    }
    
    // ===== STEP 3: RATE LIMITING =====
    $rateLimit = checkRateLimit($tokenResult['session_id']);
    if (!$rateLimit['allowed']) {
        http_response_code(429);
        echo json_encode([
            'success' => false,
            'error' => 'Rate limit exceeded',
            'retry_after' => $rateLimit['retry_after']
        ]);
        exit;
    }
    
    // ===== STEP 4: PROCESS TIKTOK ORDER =====
    $result = processTikTokOrder($videoUrl, $action, $quantity);
    
    // ===== STEP 5: LOG ACTIVITY =====
    logApiRequest([
        'session_id' => $tokenResult['session_id'],
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'video_url' => $videoUrl,
        'action' => $action,
        'quantity' => $quantity,
        'result' => $result,
        'timestamp' => time()
    ]);
    
    // ===== STEP 6: RETURN RESPONSE =====
    echo json_encode([
        'success' => true,
        'data' => $result,
        'rate_limit' => [
            'remaining' => $rateLimit['remaining'],
            'reset_in' => $rateLimit['reset_in']
        ]
    ], JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    $code = $e->getCode() ?: 500;
    http_response_code($code);
    
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'code' => $code
    ], JSON_PRETTY_PRINT);
}

exit;

// ===== FUNCTIONS =====

/**
 * Verify API Token dari headers
 */
function verifyApiToken() {
    $headers = getallheaders();
    
    // Cek required headers
    if (!isset($headers['X-Token']) || !isset($headers['X-Signature'])) {
        return ['valid' => false, 'error' => 'Token headers missing'];
    }
    
    $token = $headers['X-Token'];
    $signature = $headers['X-Signature'];
    $sessionId = $headers['X-Session-ID'] ?? '';
    $clientOnly = isset($headers['X-Client-Only']) && $headers['X-Client-Only'] === 'true';
    
    if ($clientOnly) {
        // Verify client-only token
        return verifyClientToken($token, $signature, $sessionId);
    }
    
    // Verify server token
    return verifyServerToken($token, $signature, $sessionId);
}

/**
 * Verify client-only token (generated di JavaScript)
 */
function verifyClientToken($token, $signature, $sessionId) {
    try {
        // Decode token payload
        $payloadJson = base64_decode($token);
        if (!$payloadJson) {
            return ['valid' => false, 'error' => 'Invalid token encoding'];
        }
        
        $payload = json_decode($payloadJson, true);
        if (!$payload) {
            return ['valid' => false, 'error' => 'Invalid token payload'];
        }
        
        // Check expiry
        if (isset($payload['expires']) && $payload['expires'] < time()) {
            return ['valid' => false, 'error' => 'Token expired'];
        }
        
        // Check session ID
        if (empty($sessionId) || $payload['session_id'] !== $sessionId) {
            return ['valid' => false, 'error' => 'Session mismatch'];
        }
        
        // Check user agent (basic validation)
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (isset($payload['user_agent']) && $payload['user_agent'] !== $userAgent) {
            return ['valid' => false, 'error' => 'User agent mismatch'];
        }
        
        // Verify signature
        $expectedSignature = hash_hmac('sha256', $token, API_SECRET_KEY);
        if (!hash_equals($expectedSignature, $signature)) {
            return ['valid' => false, 'error' => 'Invalid signature'];
        }
        
        // Additional check: verify browser fingerprint jika ada
        if (isset($payload['fingerprint'])) {
            $currentFingerprint = generateBrowserFingerprint();
            if ($payload['fingerprint'] !== $currentFingerprint) {
                return ['valid' => false, 'error' => 'Browser fingerprint mismatch'];
            }
        }
        
        return [
            'valid' => true,
            'session_id' => $sessionId,
            'client_only' => true
        ];
        
    } catch (Exception $e) {
        return ['valid' => false, 'error' => 'Token verification failed: ' . $e->getMessage()];
    }
}

/**
 * Verify server token (generated di token-server.php)
 */
function verifyServerToken($token, $signature, $sessionId) {
    // Cek di session storage
    $sessionKey = 'api_token_' . $sessionId;
    
    if (!isset($_SESSION[$sessionKey])) {
        return ['valid' => false, 'error' => 'Token not found in session'];
    }
    
    $storedToken = $_SESSION[$sessionKey];
    
    // Check expiry
    if (time() > $storedToken['expires']) {
        unset($_SESSION[$sessionKey]);
        return ['valid' => false, 'error' => 'Token expired'];
    }
    
    // Verify signature
    $expectedSignature = hash_hmac('sha256', $token, API_SECRET_KEY);
    if (!hash_equals($expectedSignature, $signature)) {
        return ['valid' => false, 'error' => 'Invalid signature'];
    }
    
    // Verify token matches stored token
    if ($storedToken['token'] !== $token) {
        return ['valid' => false, 'error' => 'Token mismatch'];
    }
    
    return [
        'valid' => true,
        'session_id' => $sessionId,
        'client_only' => false
    ];
}

/**
 * Generate browser fingerprint untuk validasi
 */
function generateBrowserFingerprint() {
    $components = [
        $_SERVER['HTTP_USER_AGENT'] ?? '',
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
        $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
        $_SERVER['REMOTE_ADDR'] ?? '',
        gethostname() ?: ''
    ];
    
    $fingerprintString = implode('|', $components);
    return hash('sha256', $fingerprintString);
}

/**
 * Validate TikTok URL format
 */
function isValidTikTokUrl($url) {
    $patterns = [
        '/tiktok\.com\/@[^\/]+\/video\/\d+/i',
        '/vm\.tiktok\.com\/[a-zA-Z0-9]+/i',
        '/vt\.tiktok\.com\/[a-zA-Z0-9]+/i',
        '/tiktok\.com\/t\/[a-zA-Z0-9]+\/\?/i'
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $url)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Rate limiting system
 */
function checkRateLimit($sessionId) {
    $key = 'rate_limit_' . $sessionId;
    $now = time();
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = [
            'count' => 1,
            'first_request' => $now,
            'last_request' => $now
        ];
        return ['allowed' => true, 'remaining' => MAX_REQUESTS_PER_MIN - 1, 'reset_in' => 60];
    }
    
    $data = $_SESSION[$key];
    
    // Reset jika sudah lewat 1 menit
    if ($now - $data['first_request'] > 60) {
        $_SESSION[$key] = [
            'count' => 1,
            'first_request' => $now,
            'last_request' => $now
        ];
        return ['allowed' => true, 'remaining' => MAX_REQUESTS_PER_MIN - 1, 'reset_in' => 60];
    }
    
    // Cek limit
    if ($data['count'] >= MAX_REQUESTS_PER_MIN) {
        $retryAfter = 60 - ($now - $data['first_request']);
        return [
            'allowed' => false,
            'retry_after' => $retryAfter,
            'remaining' => 0,
            'reset_in' => $retryAfter
        ];
    }
    
    // Update counter
    $_SESSION[$key]['count']++;
    $_SESSION[$key]['last_request'] = $now;
    
    $remaining = MAX_REQUESTS_PER_MIN - $_SESSION[$key]['count'];
    $resetIn = 60 - ($now - $data['first_request']);
    
    return [
        'allowed' => true,
        'remaining' => $remaining,
        'reset_in' => $resetIn
    ];
}

/**
 * Main TikTok order processing
 */
function processTikTokOrder($videoUrl, $action, $quantity) {
    // Determine service ID
    $serviceId = ($action === 'views') ? TIKTOK_VIEWS_SERVICE_ID : TIKTOK_LIKES_SERVICE_ID;
    
    // Generate UUID untuk device
    $uuid = generateUuid();
    
    // Step 1: Get Video ID
    $videoId = getVideoIdFromUrl($videoUrl);
    if (!$videoId) {
        throw new Exception('Failed to extract video ID from URL', 400);
    }
    
    // Step 2: Check service availability
    $checkResult = callZefameApi([
        'action' => 'check',
        'device' => $uuid,
        'service' => $serviceId,
        'videoId' => $videoId
    ]);
    
    if (!isset($checkResult['status']) || $checkResult['status'] !== 'success') {
        throw new Exception('Service check failed: ' . ($checkResult['message'] ?? 'Unknown error'), 503);
    }
    
    // Step 3: Process orders based on quantity
    $maxPerRequest = ($action === 'views') ? 100 : 10;
    $requestsNeeded = ceil($quantity / $maxPerRequest);
    $orders = [];
    
    for ($i = 0; $i < $requestsNeeded; $i++) {
        // Calculate quantity for this request
        $currentQuantity = min($maxPerRequest, $quantity - ($i * $maxPerRequest));
        
        $orderResult = callZefameApi([
            'service' => $serviceId,
            'link' => $videoUrl,
            'uuid' => $uuid,
            'videoId' => $videoId,
            'action' => 'order',
            'quantity' => $currentQuantity
        ], 'GET');
        
        $orders[] = [
            'request_number' => $i + 1,
            'quantity' => $currentQuantity,
            'result' => $orderResult,
            'timestamp' => time()
        ];
        
        // Delay between requests (anti-spam)
        if ($i < $requestsNeeded - 1) {
            usleep(rand(500000, 1000000)); // 0.5-1 second
        }
    }
    
    return [
        'order_id' => 'TIKTOK_' . time() . '_' . substr($uuid, 0, 8),
        'video_id' => $videoId,
        'video_url' => $videoUrl,
        'action' => $action,
        'total_quantity' => $quantity,
        'service_id' => $serviceId,
        'uuid' => $uuid,
        'requests_made' => $requestsNeeded,
        'orders' => $orders,
        'status' => 'processing',
        'estimated_completion' => '24-48 hours'
    ];
}

/**
 * Extract video ID from TikTok URL
 */
function getVideoIdFromUrl($videoUrl) {
    // Try to get from Zefame API first
    $checkResult = callZefameApi([
        'action' => 'checkVideoId',
        'link' => urlencode($videoUrl)
    ]);
    
    // Check if API returned videoId
    if (isset($checkResult['videoId'])) {
        return $checkResult['videoId'];
    }
    
    // Fallback: Extract from URL patterns
    $patterns = [
        '/\/video\/(\d+)/',
        '/video\/(\d+)/',
        '/\/(\d+)(?:\?|$)/'
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $videoUrl, $matches)) {
            return $matches[1];
        }
    }
    
    return null;
}

/**
 * Call Zefame API
 */
function callZefameApi($params, $method = 'POST') {
    $ch = curl_init();
    
    if ($method === 'GET') {
        $url = ZEFAME_API_URL . '?' . http_build_query($params);
        curl_setopt($ch, CURLOPT_URL, $url);
    } else {
        curl_setopt($ch, CURLOPT_URL, ZEFAME_API_URL);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    }
    
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded'
        ]
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    // Parse response
    $data = json_decode($response, true);
    
    // If not JSON, try to parse as string
    if (!$data && $response) {
        parse_str($response, $parsed);
        $data = $parsed ?: $response;
    }
    
    return [
        'http_code' => $httpCode,
        'success' => ($httpCode >= 200 && $httpCode < 300),
        'raw_response' => $response,
        'data' => $data,
        'error' => $error
    ];
}

/**
 * Generate UUID v4
 */
function generateUuid() {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

/**
 * Log API requests untuk monitoring
 */
function logApiRequest($data) {
    $logDir = __DIR__ . '/logs';
    
    // Create logs directory jika belum ada
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    $logFile = $logDir . '/api_requests_' . date('Y-m-d') . '.log';
    
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $data['ip'],
        'session_id' => substr($data['session_id'], 0, 20),
        'video_url' => substr($data['video_url'], 0, 100),
        'action' => $data['action'],
        'quantity' => $data['quantity'],
        'success' => $data['result']['success'] ?? false
    ];
    
    // Append ke log file
    file_put_contents(
        $logFile,
        json_encode($logEntry) . PHP_EOL,
        FILE_APPEND | LOCK_EX
    );
    
    // Rotate log files setiap bulan (keep 30 days)
    $oldLogs = glob($logDir . '/api_requests_*.log');
    $keepDate = strtotime('-30 days');
    
    foreach ($oldLogs as $oldLog) {
        if (filemtime($oldLog) < $keepDate) {
            @unlink($oldLog);
        }
    }
}
?>
