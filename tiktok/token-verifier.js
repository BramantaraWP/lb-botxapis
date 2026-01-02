/**
 * Token Verification System untuk TikTok API
 * Token hanya valid di browser asli
 */

class TokenVerifier {
    constructor() {
        this.token = null;
        this.tokenExpiry = null;
        this.sessionId = this.generateSessionId();
        this.verificationAttempts = 0;
        this.maxAttempts = 3;
        
        // Auto initialize saat page load
        this.initialize();
    }
    
    /**
     * Initialize token system
     */
    initialize() {
        // Cek apakah di browser asli
        if (!this.isRealBrowser()) {
            console.warn('[TokenVerifier] Not a real browser environment');
            return false;
        }
        
        // Coba load token dari localStorage
        this.loadTokenFromStorage();
        
        // Setup auto-refresh token
        this.setupAutoRefresh();
        
        // Setup page visibility change handler
        this.setupVisibilityHandler();
        
        return true;
    }
    
    /**
     * Generate new token dari server
     */
    async generateToken() {
        // Blok jika bukan browser asli
        if (!this.isRealBrowser()) {
            throw new Error('Token generation requires real browser');
        }
        
        // Rate limiting check
        if (this.verificationAttempts >= this.maxAttempts) {
            throw new Error('Too many token generation attempts');
        }
        
        this.verificationAttempts++;
        
        try {
            // Collect browser fingerprints
            const fingerprint = this.getBrowserFingerprint();
            
            // Request token dari server
            const response = await fetch('/token-server.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': this.sessionId
                },
                body: JSON.stringify({
                    action: 'generate_token',
                    fingerprint: fingerprint,
                    timestamp: Date.now()
                })
            });
            
            if (!response.ok) {
                throw new Error(`Server responded with ${response.status}`);
            }
            
            const data = await response.json();
            
            if (!data.success) {
                throw new Error(data.error || 'Failed to generate token');
            }
            
            // Save token
            this.token = data.token;
            this.tokenExpiry = Date.now() + (data.expires_in * 1000);
            
            // Save to localStorage
            this.saveTokenToStorage();
            
            console.log('[TokenVerifier] New token generated');
            return this.token;
            
        } catch (error) {
            console.error('[TokenVerifier] Token generation failed:', error);
            
            // Fallback: Generate client-only token (less secure)
            if (error.message.includes('real browser')) {
                this.generateClientToken();
                return this.token;
            }
            
            throw error;
        }
    }
    
    /**
     * Generate token hanya di client (fallback)
     */
    generateClientToken() {
        const payload = {
            session_id: this.sessionId,
            user_agent: navigator.userAgent,
            timestamp: Date.now(),
            expires: Date.now() + (3 * 60 * 60 * 1000), // 3 jam
            client_only: true
        };
        
        // Encode payload
        const encodedPayload = btoa(JSON.stringify(payload));
        
        // Generate signature dengan client secret
        const clientSecret = this.getClientSecret();
        const signature = this.hashString(encodedPayload + clientSecret);
        
        this.token = {
            payload: encodedPayload,
            signature: signature,
            client_only: true
        };
        
        this.tokenExpiry = payload.expires;
        this.saveTokenToStorage();
        
        console.warn('[TokenVerifier] Using client-only token (less secure)');
        return this.token;
    }
    
    /**
     * Verifikasi token sebelum digunakan
     */
    async verifyToken() {
        // Cek apakah token ada
        if (!this.token) {
            console.log('[TokenVerifier] No token found, generating new one');
            return await this.generateToken();
        }
        
        // Cek expiry
        if (this.isTokenExpired()) {
            console.log('[TokenVerifier] Token expired, generating new one');
            return await this.generateToken();
        }
        
        // Untuk client-only token, validasi lokal saja
        if (this.token.client_only) {
            if (!this.validateClientToken()) {
                console.log('[TokenVerifier] Client token invalid, generating new');
                return await this.generateToken();
            }
            return this.token;
        }
        
        // Untuk server token, verifikasi ke server
        try {
            const response = await fetch('/token-server.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    action: 'verify_token',
                    token: this.token,
                    session_id: this.sessionId
                })
            });
            
            const data = await response.json();
            
            if (data.valid) {
                console.log('[TokenVerifier] Token verified');
                return this.token;
            } else {
                console.log('[TokenVerifier] Token invalid, generating new');
                return await this.generateToken();
            }
            
        } catch (error) {
            console.error('[TokenVerifier] Token verification failed:', error);
            
            // Fallback ke client token
            this.generateClientToken();
            return this.token;
        }
    }
    
    /**
     * Get verified token untuk API request
     */
    async getVerifiedToken() {
        const token = await this.verifyToken();
        
        if (token.client_only) {
            return {
                'X-Token': token.payload,
                'X-Signature': token.signature,
                'X-Client-Only': 'true'
            };
        }
        
        return {
            'X-Token': token.token,
            'X-Signature': token.signature,
            'X-Session-ID': this.sessionId
        };
    }
    
    /**
     * Cek apakah token expired
     */
    isTokenExpired() {
        if (!this.tokenExpiry) return true;
        return Date.now() >= this.tokenExpiry;
    }
    
    /**
     * Validasi client-only token
     */
    validateClientToken() {
        if (!this.token || !this.token.payload || !this.token.signature) {
            return false;
        }
        
        try {
            // Decode payload
            const payloadStr = atob(this.token.payload);
            const payload = JSON.parse(payloadStr);
            
            // Cek expiry
            if (payload.expires < Date.now()) {
                return false;
            }
            
            // Cek session ID
            if (payload.session_id !== this.sessionId) {
                return false;
            }
            
            // Verify signature
            const clientSecret = this.getClientSecret();
            const expectedSignature = this.hashString(this.token.payload + clientSecret);
            
            return this.token.signature === expectedSignature;
            
        } catch (error) {
            console.error('[TokenVerifier] Token validation error:', error);
            return false;
        }
    }
    
    /**
     * Deteksi browser asli vs bot/curl
     */
    isRealBrowser() {
        // Cek apakah di environment browser
        if (typeof window === 'undefined' || typeof document === 'undefined') {
            return false;
        }
        
        // Cek user agent untuk bot/curl
        const ua = navigator.userAgent.toLowerCase();
        const botPatterns = [
            'bot', 'crawl', 'spider', 'curl', 'wget', 'python',
            'java', 'node', 'postman', 'insomnia', 'fetch',
            'axios', 'http-client', 'libwww', 'php', 'go-http'
        ];
        
        for (const pattern of botPatterns) {
            if (ua.includes(pattern)) {
                console.warn(`[TokenVerifier] Bot detected: ${pattern}`);
                return false;
            }
        }
        
        // Cek WebDriver (Selenium/Puppeteer)
        if (navigator.webdriver === true) return false;
        if (window.callPhantom || window._phantom) return false;
        if (window.__nightmare) return false;
        
        // Cek screen properties
        if (!screen.width || !screen.height) return false;
        if (screen.width < 100 || screen.height < 100) return false;
        
        // Cek plugin (browser punya, bot tidak)
        if (navigator.plugins.length === 0) return false;
        
        // Cek language (bot sering tidak set)
        if (!navigator.language) return false;
        
        return true;
    }
    
    /**
     * Generate browser fingerprint
     */
    getBrowserFingerprint() {
        const components = [
            navigator.userAgent,
            navigator.language,
            screen.width + 'x' + screen.height,
            screen.colorDepth,
            new Date().getTimezoneOffset(),
            !!navigator.cookieEnabled,
            navigator.hardwareConcurrency || 'unknown',
            navigator.platform,
            navigator.maxTouchPoints || 0,
            window.devicePixelRatio || 1
        ];
        
        const fingerprintString = components.join('|');
        return this.hashString(fingerprintString);
    }
    
    /**
     * Simple hash function
     */
    hashString(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(16);
    }
    
    /**
     * Generate session ID
     */
    generateSessionId() {
        return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
    
    /**
     * Get client secret dari cookies/localStorage
     */
    getClientSecret() {
        // Coba dari localStorage dulu
        let secret = localStorage.getItem('client_secret');
        
        if (!secret) {
            // Generate baru
            secret = 'client_' + Math.random().toString(36).substr(2, 16) + 
                    '_' + Date.now().toString(36);
            localStorage.setItem('client_secret', secret);
        }
        
        return secret;
    }
    
    /**
     * Load token dari localStorage
     */
    loadTokenFromStorage() {
        try {
            const saved = localStorage.getItem('api_token');
            if (saved) {
                const data = JSON.parse(saved);
                
                // Cek expiry
                if (data.expiry && data.expiry > Date.now()) {
                    this.token = data.token;
                    this.tokenExpiry = data.expiry;
                    console.log('[TokenVerifier] Token loaded from storage');
                } else {
                    localStorage.removeItem('api_token');
                }
            }
        } catch (error) {
            console.error('[TokenVerifier] Failed to load token from storage:', error);
            localStorage.removeItem('api_token');
        }
    }
    
    /**
     * Save token ke localStorage
     */
    saveTokenToStorage() {
        try {
            const data = {
                token: this.token,
                expiry: this.tokenExpiry,
                saved_at: Date.now()
            };
            localStorage.setItem('api_token', JSON.stringify(data));
        } catch (error) {
            console.error('[TokenVerifier] Failed to save token:', error);
        }
    }
    
    /**
     * Setup auto-refresh token
     */
    setupAutoRefresh() {
        // Refresh token setiap 2.5 jam (9000 detik)
        setInterval(() => {
            if (this.isTokenExpired() || this.tokenExpiry - Date.now() < 1800000) {
                console.log('[TokenVerifier] Auto-refreshing token');
                this.generateToken().catch(console.error);
            }
        }, 9000000); // 2.5 jam
    }
    
    /**
     * Handle page visibility change
     */
    setupVisibilityHandler() {
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.isTokenExpired()) {
                console.log('[TokenVerifier] Page visible, refreshing expired token');
                this.generateToken().catch(console.error);
            }
        });
    }
    
    /**
     * Clear token (logout)
     */
    clearToken() {
        this.token = null;
        this.tokenExpiry = null;
        localStorage.removeItem('api_token');
        console.log('[TokenVerifier] Token cleared');
    }
}

// Global instance
window.TokenVerifier = new TokenVerifier();

// Auto-export untuk module system
if (typeof module !== 'undefined' && module.exports) {
    module.exports = TokenVerifier;
                            }
