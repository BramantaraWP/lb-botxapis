<?php
require_once 'config.php';

class TikTokZefameAPI {
    
    /**
     * Main function: Process TikTok Order
     * @param string $videoUrl - TikTok video URL
     * @param string $action - 'views' or 'likes'
     * @param int $quantity - How many views/likes
     * @return array - Result
     */
    public function processTikTokOrder($videoUrl, $action = 'views', $quantity = 100) {
        // Validate TikTok URL
        if (!$this->isTikTokUrl($videoUrl)) {
            return ['error' => 'Invalid TikTok URL'];
        }
        
        // Get service ID based on action
        $serviceId = ($action === 'views') ? TIKTOK_VIEWS_SERVICE_ID : TIKTOK_LIKES_SERVICE_ID;
        
        // Generate UUID for this session
        $uuid = $this->generateUuid();
        
        // STEP 1: Get Video ID
        $videoId = $this->getVideoId($videoUrl);
        if (!$videoId) {
            return ['error' => 'Cannot extract video ID'];
        }
        
        // STEP 2: Check Service
        $checkResult = $this->zefameRequest([
            'action' => 'check',
            'device' => $uuid,
            'service' => $serviceId,
            'videoId' => $videoId
        ]);
        
        if (!$checkResult['success']) {
            return ['error' => 'Service unavailable', 'details' => $checkResult];
        }
        
        // STEP 3: Order (multiple times for quantity)
        $orders = [];
        $maxPerRequest = ($action === 'views') ? 100 : 10; // Views lebih banyak per request
        
        $requestsNeeded = ceil($quantity / $maxPerRequest);
        
        for ($i = 1; $i <= $requestsNeeded; $i++) {
            $orderData = [
                'service' => $serviceId,
                'link' => $videoUrl,
                'uuid' => $uuid,
                'videoId' => $videoId,
                'action' => 'order'
            ];
            
            // Untuk action=order, pakai GET
            $orderResult = $this->zefameRequest($orderData, 'GET');
            
            $orders[] = [
                'request' => $i,
                'result' => $orderResult
            ];
            
            // Delay antar request (jangan spam)
            if ($i < $requestsNeeded) {
                usleep(500000); // 0.5 second
            }
        }
        
        return [
            'success' => true,
            'action' => $action,
            'video_url' => $videoUrl,
            'video_id' => $videoId,
            'uuid' => $uuid,
            'quantity_requested' => $quantity,
            'requests_made' => $requestsNeeded,
            'orders' => $orders
        ];
    }
    
    /**
     * Extract video ID from TikTok URL
     */
    private function getVideoId($videoUrl) {
        // Coba dapetin dari checkVideoId API
        $checkResult = $this->zefameRequest([
            'action' => 'checkVideoId',
            'link' => urlencode($videoUrl)
        ]);
        
        // Jika API ngasih videoId
        if (isset($checkResult['data']['videoId'])) {
            return $checkResult['data']['videoId'];
        }
        
        // Fallback: Extract from URL pattern
        // Pattern 1: /video/123456789
        preg_match('/\/video\/(\d+)/', $videoUrl, $matches);
        if (isset($matches[1])) {
            return $matches[1];
        }
        
        // Pattern 2: /@username/video/123456789
        preg_match('/video\/(\d+)/', $videoUrl, $matches);
        if (isset($matches[1])) {
            return $matches[1];
        }
        
        return null;
    }
    
    /**
     * Make request to Zefame API
     */
    private function zefameRequest($params, $method = 'POST') {
        $ch = curl_init();
        
        if ($method === 'GET') {
            // Build query string for GET
            $url = ZEFAME_API_URL . '?' . http_build_query($params);
            curl_setopt($ch, CURLOPT_URL, $url);
        } else {
            // POST request
            curl_setopt($ch, CURLOPT_URL, ZEFAME_API_URL);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        }
        
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Content-Type: application/x-www-form-urlencoded'
            ]
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        // Parse response
        $data = json_decode($response, true);
        
        // Jika bukan JSON, try to parse as key-value
        if (!$data && $response) {
            parse_str($response, $parsed);
            $data = $parsed;
        }
        
        return [
            'success' => ($httpCode === 200),
            'http_code' => $httpCode,
            'raw_response' => $response,
            'data' => $data ?: []
        ];
    }
    
    /**
     * Validate TikTok URL
     */
    private function isTikTokUrl($url) {
        $patterns = [
            '/tiktok\.com\/@[^\/]+\/video\/\d+/',
            '/vm\.tiktok\.com\/[a-zA-Z0-9]+/',
            '/vt\.tiktok\.com\/[a-zA-Z0-9]+/'
        ];
        
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $url)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate UUID v4
     */
    private function generateUuid() {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }
}
