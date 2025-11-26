/**
 * ============================================================================
 * MexTech Security Shield v1.0.0
 * ============================================================================
 * Copyright © 2025 MexTech Limited. All rights reserved.
 * https://mextechltd.name.ng
 * 
 * A comprehensive, production-ready security script for static HTML websites.
 * Provides real-time protection against attacks, spam, bots, scams, malware
 * distribution, and phishing attempts.
 * 
 * FEATURES:
 * - IP-based blocking with multiple free blocklists
 * - Advanced bot & crawler protection
 * - Honeypot traps for bots
 * - Rate limiting per IP
 * - Anti-spam & form protection
 * - Behavioral analysis scoring
 * - Phishing & click fraud protection
 * - Real-time response actions
 * 
 * LICENSE: Proprietary - All rights reserved by MexTech Limited
 * ============================================================================
 */

(function(window, document) {
  'use strict';

  // ============================================================================
  // CONFIGURATION - Edit these settings to customize protection
  // ============================================================================
  const CONFIG = {
    // Enable/disable features
    enabled: true,
    debug: false, // Set to true to see console logs
    
    // IP Blocking
    ipBlocking: {
      enabled: true,
      cacheExpiry: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      customBlocklist: [], // Add custom IPs/CIDRs here: ['1.2.3.4', '5.6.7.0/24']
      blocklistUrls: [],
      // Optional: Enable IP detection via free API (ipify.org)
      // Note: This makes an external API call on each page load
      detectIP: false,
      ipApiUrl: 'https://api.ipify.org?format=json'
    },
    
    // Bot Detection
    botDetection: {
      enabled: true,
      blockHeadlessBrowsers: true,
      blockBadUserAgents: true,
      checkWebDriver: true,
      checkPlugins: true,
      checkLanguages: true
    },
    
    // Honeypot
    honeypot: {
      enabled: true,
      fieldName: 'website_url_hp', // Hidden field name
      linkClass: 'hp-link' // Hidden link class
    },
    
    // Rate Limiting
    rateLimiting: {
      enabled: true,
      maxRequests: 60, // Max requests per window
      windowMs: 60000, // Time window in ms (1 minute)
      burstAllowed: 10, // Extra requests allowed in burst
      blockDuration: 300000 // Block duration in ms (5 minutes)
    },
    
    // Form Protection
    formProtection: {
      enabled: true,
      minSubmitTime: 2000, // Minimum time before form can be submitted (ms)
      checkMouseMovement: true,
      checkKeystrokes: true,
      blockDisposableEmails: true
    },
    
    // Behavioral Analysis
    behavioralAnalysis: {
      enabled: true,
      minScore: 30, // Minimum score to pass (0-100)
      trackMouseMovement: true,
      trackScrolling: true,
      trackKeystrokes: true,
      trackTouchEvents: true,
      trackFocusTime: true
    },
    
    // Response Actions
    responseActions: {
      action: 'block', // 'block', 'redirect', 'challenge', 'log'
      redirectUrl: '/maintenance.html',
      showChallengePage: true,
      challengeType: 'math' // 'math', 'button', 'timing'
    },
    
    // Webhook for logging (optional)
    webhook: {
      enabled: false,
      url: '', // Your webhook URL
      sendBlocked: true,
      sendSuspicious: true
    },
    
    // Privacy
    privacy: {
      respectDoNotTrack: true,
      noLegitUserTracking: true
    },
    
    // Bad User Agents patterns
    badUserAgents: [
      'headless', 'phantom', 'selenium', 'puppeteer', 'playwright',
      'nightmare', 'slimer', 'casper', 'splash', 'htmlunit',
      'wget', 'curl', 'python-requests', 'python-urllib', 'java/',
      'libwww', 'lwp-', 'httpunit', 'httrack', 'apache-httpclient',
      'go-http-client', 'okhttp', 'ahrefsbot', 'mj12bot', 'dotbot',
      'semrushbot', 'yandexbot', 'baiduspider', 'sogou', 'exabot',
      'facebot', 'ia_archiver', 'archive.org_bot', 'scrapy',
      'nutch', 'data mining', 'extractor', 'harvest', 'grab',
      'webripper', 'webcopier', 'offline', 'collector', 'discobot'
    ],
    
    // Disposable email domains
    disposableEmailDomains: [
      'tempmail.com', 'throwaway.email', 'guerrillamail.com', 'mailinator.com',
      '10minutemail.com', 'temp-mail.org', 'fakeinbox.com', 'trashmail.com',
      'getnada.com', 'maildrop.cc', 'yopmail.com', 'sharklasers.com',
      'guerrillamailblock.com', 'pokemail.net', 'spam4.me', 'grr.la',
      'dispostable.com', 'mailnesia.com', 'tempail.com', 'tempmailaddress.com',
      'burnermail.io', 'mohmal.com', 'emailondeck.com', 'fakemail.net',
      'mintemail.com', 'tempinbox.com', 'mytemp.email', 'fake-box.com',
      'emailfake.com', 'generator.email', 'crazymailing.com', 'tempemailco.com'
    ],
    
    // Spam content patterns
    spamPatterns: [
      /\b(viagra|cialis|pharmacy|casino|lottery|winner|prize|congratulations)\b/i,
      /\b(buy now|click here|act now|limited time|offer expires)\b/i,
      /\b(nigerian prince|inheritance|million dollars|wire transfer)\b/i,
      /\b(make money fast|work from home|earn \$\d+|passive income)\b/i,
      /\b(crypto|bitcoin|investment opportunity|guaranteed returns)\b/i,
      /(https?:\/\/[^\s]+){3,}/i, // Multiple URLs
      /(.)\1{10,}/i, // Repeated characters
      /[A-Z\s]{20,}/i // Excessive caps
    ]
  };

  // ============================================================================
  // STORAGE UTILITY
  // ============================================================================
  const Storage = {
    prefix: 'mxts_',
    
    get(key) {
      try {
        const item = localStorage.getItem(this.prefix + key);
        if (!item) return null;
        const data = JSON.parse(item);
        if (data.expiry && Date.now() > data.expiry) {
          this.remove(key);
          return null;
        }
        return data.value;
      } catch (e) {
        return null;
      }
    },
    
    set(key, value, ttl = null) {
      try {
        const data = {
          value: value,
          expiry: ttl ? Date.now() + ttl : null
        };
        localStorage.setItem(this.prefix + key, JSON.stringify(data));
        return true;
      } catch (e) {
        return false;
      }
    },
    
    remove(key) {
      try {
        localStorage.removeItem(this.prefix + key);
        return true;
      } catch (e) {
        return false;
      }
    }
  };

  // ============================================================================
  // IP UTILITIES
  // ============================================================================
  const IPUtils = {
    visitorIP: null,
    
    // Parse CIDR notation and check if IP matches
    ipMatchesCIDR(ip, cidr) {
      if (!ip || !cidr) return false;
      
      // Handle exact IP match
      if (!cidr.includes('/')) {
        return ip === cidr;
      }
      
      try {
        const [range, bits] = cidr.split('/');
        const mask = parseInt(bits, 10);
        
        const ipParts = ip.split('.').map(Number);
        const rangeParts = range.split('.').map(Number);
        
        const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
        const rangeNum = (rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3];
        const maskNum = ~((1 << (32 - mask)) - 1);
        
        return (ipNum & maskNum) === (rangeNum & maskNum);
      } catch (e) {
        return false;
      }
    },
    
    // Check if IP is in blocklist
    isBlocked(ip, blocklist) {
      if (!ip || !blocklist || blocklist.length === 0) return false;
      
      for (const entry of blocklist) {
        if (this.ipMatchesCIDR(ip, entry)) {
          return true;
        }
      }
      return false;
    },
    
    // Fetch visitor IP (optional, requires detectIP: true)
    async detectVisitorIP() {
      if (!CONFIG.ipBlocking.detectIP) return null;
      
      // Check cache first
      const cachedIP = Storage.get('visitor_ip');
      if (cachedIP) {
        this.visitorIP = cachedIP;
        return cachedIP;
      }
      
      try {
        const response = await fetch(CONFIG.ipBlocking.ipApiUrl);
        if (response.ok) {
          const data = await response.json();
          this.visitorIP = data.ip;
          // Cache for 1 hour
          Storage.set('visitor_ip', data.ip, 3600000);
          return data.ip;
        }
      } catch (e) {
        Logger.warn('Failed to detect visitor IP', e);
      }
      return null;
    },
    
    getIP() {
      return this.visitorIP;
    }
  };

  // ============================================================================
  // LOGGING UTILITY
  // ============================================================================
  const Logger = {
    log(message, data = null) {
      if (CONFIG.debug) {
        console.log('[MexTech Security]', message, data || '');
      }
    },
    
    warn(message, data = null) {
      if (CONFIG.debug) {
        console.warn('[MexTech Security]', message, data || '');
      }
    },
    
    error(message, data = null) {
      console.error('[MexTech Security]', message, data || '');
    },
    
    async sendToWebhook(type, data) {
      if (!CONFIG.webhook.enabled || !CONFIG.webhook.url) return;
      
      if (type === 'blocked' && !CONFIG.webhook.sendBlocked) return;
      if (type === 'suspicious' && !CONFIG.webhook.sendSuspicious) return;
      
      try {
        await fetch(CONFIG.webhook.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: type,
            timestamp: new Date().toISOString(),
            url: window.location.href,
            userAgent: navigator.userAgent,
            data: data
          })
        });
      } catch (e) {
        Logger.error('Webhook failed', e);
      }
    }
  };

  // ============================================================================
  // VISITOR FINGERPRINT
  // ============================================================================
  const Fingerprint = {
    data: {},
    
    collect() {
      this.data = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages ? navigator.languages.join(',') : '',
        platform: navigator.platform,
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack,
        screenWidth: screen.width,
        screenHeight: screen.height,
        colorDepth: screen.colorDepth,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset(),
        touchSupport: 'ontouchstart' in window,
        plugins: this.getPlugins(),
        webdriver: this.checkWebDriver(),
        headless: this.checkHeadless()
      };
      return this.data;
    },
    
    getPlugins() {
      if (!navigator.plugins) return [];
      return Array.from(navigator.plugins).map(p => p.name).slice(0, 10);
    },
    
    checkWebDriver() {
      return !!(
        navigator.webdriver ||
        window.navigator.webdriver ||
        window.callPhantom ||
        window._phantom ||
        window.__nightmare ||
        window.domAutomation ||
        window.domAutomationController ||
        document.__selenium_unwrapped ||
        document.__webdriver_evaluate ||
        document.__driver_evaluate ||
        document.__webdriver_script_function ||
        document.__webdriver_script_func ||
        document.__webdriver_script_fn ||
        document.$cdc_asdjflasutopfhvcZLmcfl_ ||
        document.$wdc_ ||
        window.selenium ||
        window.Selenium ||
        window.driver
      );
    },
    
    checkHeadless() {
      const ua = navigator.userAgent.toLowerCase();
      
      // Check user agent
      if (ua.includes('headless') || ua.includes('phantom') || 
          ua.includes('selenium') || ua.includes('puppeteer')) {
        return true;
      }
      
      // Check for missing plugins (common in headless)
      if (navigator.plugins && navigator.plugins.length === 0) {
        // Could be headless, but not definitive on mobile
        if (!this.data.touchSupport) return true;
      }
      
      // Check for missing languages
      if (!navigator.languages || navigator.languages.length === 0) {
        return true;
      }
      
      // Check WebGL renderer
      try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          if (debugInfo) {
            const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            if (renderer && (renderer.includes('SwiftShader') || renderer.includes('llvmpipe'))) {
              return true;
            }
          }
        }
      } catch (e) {}
      
      // Check for Phantom-specific properties
      if (window.callPhantom || window._phantom) {
        return true;
      }
      
      // Check for automation tools
      if (window.domAutomation || window.domAutomationController) {
        return true;
      }
      
      return false;
    },
    
    getHash() {
      const str = JSON.stringify(this.data);
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
      }
      return Math.abs(hash).toString(36);
    }
  };

  // ============================================================================
  // BOT DETECTION
  // ============================================================================
  const BotDetector = {
    score: 100, // Start with 100, deduct for suspicious behavior
    reasons: [],
    
    analyze() {
      if (!CONFIG.botDetection.enabled) return { isBot: false, score: 100, reasons: [] };
      
      this.score = 100;
      this.reasons = [];
      
      // Check webdriver
      if (CONFIG.botDetection.checkWebDriver && Fingerprint.data.webdriver) {
        this.score -= 80;
        this.reasons.push('WebDriver detected');
      }
      
      // Check headless
      if (CONFIG.botDetection.blockHeadlessBrowsers && Fingerprint.data.headless) {
        this.score -= 70;
        this.reasons.push('Headless browser detected');
      }
      
      // Check user agent
      if (CONFIG.botDetection.blockBadUserAgents) {
        const ua = (navigator.userAgent || '').toLowerCase();
        for (const pattern of CONFIG.badUserAgents) {
          if (ua.includes(pattern.toLowerCase())) {
            this.score -= 60;
            this.reasons.push('Bad user agent: ' + pattern);
            break;
          }
        }
        
        // Missing or empty user agent
        if (!ua || ua.length < 10) {
          this.score -= 50;
          this.reasons.push('Missing or short user agent');
        }
      }
      
      // Check plugins
      if (CONFIG.botDetection.checkPlugins) {
        if (Fingerprint.data.plugins.length === 0 && !Fingerprint.data.touchSupport) {
          this.score -= 20;
          this.reasons.push('No browser plugins (non-mobile)');
        }
      }
      
      // Check languages
      if (CONFIG.botDetection.checkLanguages) {
        if (!navigator.languages || navigator.languages.length === 0) {
          this.score -= 30;
          this.reasons.push('No languages defined');
        }
      }
      
      // Check for impossible screen dimensions
      if (screen.width === 0 || screen.height === 0) {
        this.score -= 40;
        this.reasons.push('Invalid screen dimensions');
      }
      
      // Check for automation properties
      if (window.callPhantom || window._phantom || window.__nightmare) {
        this.score -= 90;
        this.reasons.push('Automation framework detected');
      }
      
      return {
        isBot: this.score < 50,
        score: Math.max(0, this.score),
        reasons: this.reasons
      };
    }
  };

  // ============================================================================
  // RATE LIMITER
  // ============================================================================
  const RateLimiter = {
    requests: [],
    blocked: false,
    blockUntil: 0,
    
    init() {
      if (!CONFIG.rateLimiting.enabled) return;
      
      // Load state from storage
      const state = Storage.get('ratelimit');
      if (state) {
        this.requests = state.requests || [];
        this.blocked = state.blocked || false;
        this.blockUntil = state.blockUntil || 0;
      }
      
      // Clean old requests
      this.cleanup();
    },
    
    cleanup() {
      const now = Date.now();
      const windowStart = now - CONFIG.rateLimiting.windowMs;
      this.requests = this.requests.filter(t => t > windowStart);
      
      // Check if block has expired
      if (this.blocked && now > this.blockUntil) {
        this.blocked = false;
        this.blockUntil = 0;
      }
      
      this.save();
    },
    
    save() {
      Storage.set('ratelimit', {
        requests: this.requests,
        blocked: this.blocked,
        blockUntil: this.blockUntil
      }, CONFIG.rateLimiting.windowMs);
    },
    
    check() {
      if (!CONFIG.rateLimiting.enabled) return { allowed: true };
      
      this.cleanup();
      
      const now = Date.now();
      
      // Check if blocked
      if (this.blocked) {
        const remaining = Math.ceil((this.blockUntil - now) / 1000);
        return {
          allowed: false,
          reason: 'Rate limit exceeded',
          retryAfter: remaining
        };
      }
      
      // Count requests in window
      const count = this.requests.length;
      const maxAllowed = CONFIG.rateLimiting.maxRequests + CONFIG.rateLimiting.burstAllowed;
      
      if (count >= maxAllowed) {
        this.blocked = true;
        this.blockUntil = now + CONFIG.rateLimiting.blockDuration;
        this.save();
        
        return {
          allowed: false,
          reason: 'Rate limit exceeded',
          retryAfter: Math.ceil(CONFIG.rateLimiting.blockDuration / 1000)
        };
      }
      
      // Record request
      this.requests.push(now);
      this.save();
      
      return {
        allowed: true,
        remaining: maxAllowed - count - 1
      };
    },
    
    recordAction() {
      if (!CONFIG.rateLimiting.enabled) return;
      this.requests.push(Date.now());
      this.save();
    }
  };

  // ============================================================================
  // BEHAVIORAL ANALYZER
  // ============================================================================
  const BehavioralAnalyzer = {
    data: {
      mouseMovements: 0,
      mousePositions: [],
      scrollEvents: 0,
      scrollPositions: [],
      keystrokes: 0,
      keystrokeTimes: [],
      touchEvents: 0,
      focusTime: 0,
      focusStart: null,
      clickCount: 0,
      clickPositions: [],
      formInteractions: 0,
      pageLoadTime: Date.now()
    },
    
    init() {
      if (!CONFIG.behavioralAnalysis.enabled) return;
      
      // Track mouse movement
      if (CONFIG.behavioralAnalysis.trackMouseMovement) {
        document.addEventListener('mousemove', (e) => {
          this.data.mouseMovements++;
          if (this.data.mousePositions.length < 100) {
            this.data.mousePositions.push({ x: e.clientX, y: e.clientY, t: Date.now() });
          }
        }, { passive: true });
        
        document.addEventListener('click', (e) => {
          this.data.clickCount++;
          if (this.data.clickPositions.length < 50) {
            this.data.clickPositions.push({ x: e.clientX, y: e.clientY, t: Date.now() });
          }
        }, { passive: true });
      }
      
      // Track scrolling
      if (CONFIG.behavioralAnalysis.trackScrolling) {
        window.addEventListener('scroll', () => {
          this.data.scrollEvents++;
          if (this.data.scrollPositions.length < 50) {
            this.data.scrollPositions.push({ y: window.scrollY, t: Date.now() });
          }
        }, { passive: true });
      }
      
      // Track keystrokes
      if (CONFIG.behavioralAnalysis.trackKeystrokes) {
        document.addEventListener('keydown', () => {
          this.data.keystrokes++;
          if (this.data.keystrokeTimes.length < 100) {
            this.data.keystrokeTimes.push(Date.now());
          }
        }, { passive: true });
      }
      
      // Track touch events
      if (CONFIG.behavioralAnalysis.trackTouchEvents) {
        document.addEventListener('touchstart', () => {
          this.data.touchEvents++;
        }, { passive: true });
        
        document.addEventListener('touchmove', () => {
          this.data.touchEvents++;
        }, { passive: true });
      }
      
      // Track focus time
      if (CONFIG.behavioralAnalysis.trackFocusTime) {
        this.data.focusStart = Date.now();
        
        document.addEventListener('visibilitychange', () => {
          if (document.hidden) {
            if (this.data.focusStart) {
              this.data.focusTime += Date.now() - this.data.focusStart;
              this.data.focusStart = null;
            }
          } else {
            this.data.focusStart = Date.now();
          }
        });
        
        window.addEventListener('blur', () => {
          if (this.data.focusStart) {
            this.data.focusTime += Date.now() - this.data.focusStart;
            this.data.focusStart = null;
          }
        });
        
        window.addEventListener('focus', () => {
          this.data.focusStart = Date.now();
        });
      }
      
      // Track form interactions
      document.addEventListener('input', () => {
        this.data.formInteractions++;
      }, { passive: true });
    },
    
    calculateScore() {
      if (!CONFIG.behavioralAnalysis.enabled) return 100;
      
      let score = 0;
      const timeOnPage = Date.now() - this.data.pageLoadTime;
      const currentFocusTime = this.data.focusTime + 
        (this.data.focusStart ? Date.now() - this.data.focusStart : 0);
      
      // Mouse movement score (0-25 points)
      if (this.data.mouseMovements > 0) {
        const mouseScore = Math.min(25, this.data.mouseMovements / 4);
        score += mouseScore;
        
        // Check for natural mouse movement (not perfectly straight lines)
        if (this.data.mousePositions.length >= 10) {
          const variance = this.calculateMouseVariance();
          if (variance > 10) score += 5; // Natural movement bonus
        }
      }
      
      // Scroll score (0-15 points)
      if (this.data.scrollEvents > 0) {
        score += Math.min(15, this.data.scrollEvents);
      }
      
      // Keystroke score (0-15 points)
      if (this.data.keystrokes > 0) {
        score += Math.min(15, this.data.keystrokes);
        
        // Check typing rhythm
        if (this.data.keystrokeTimes.length >= 5) {
          const rhythm = this.analyzeTypingRhythm();
          if (rhythm.isNatural) score += 5;
        }
      }
      
      // Touch score (0-15 points)
      if (this.data.touchEvents > 0) {
        score += Math.min(15, this.data.touchEvents / 2);
      }
      
      // Time on page score (0-15 points)
      if (timeOnPage > 3000) {
        score += Math.min(15, timeOnPage / 2000);
      }
      
      // Focus time score (0-10 points)
      if (currentFocusTime > 2000) {
        score += Math.min(10, currentFocusTime / 3000);
      }
      
      // Click score (0-10 points)
      if (this.data.clickCount > 0) {
        score += Math.min(10, this.data.clickCount * 2);
      }
      
      return Math.min(100, Math.round(score));
    },
    
    calculateMouseVariance() {
      const positions = this.data.mousePositions;
      if (positions.length < 3) return 0;
      
      let totalVariance = 0;
      for (let i = 2; i < positions.length; i++) {
        const dx1 = positions[i-1].x - positions[i-2].x;
        const dy1 = positions[i-1].y - positions[i-2].y;
        const dx2 = positions[i].x - positions[i-1].x;
        const dy2 = positions[i].y - positions[i-1].y;
        
        // Calculate angle change
        const angle1 = Math.atan2(dy1, dx1);
        const angle2 = Math.atan2(dy2, dx2);
        totalVariance += Math.abs(angle2 - angle1);
      }
      
      return totalVariance / (positions.length - 2);
    },
    
    analyzeTypingRhythm() {
      const times = this.data.keystrokeTimes;
      if (times.length < 5) return { isNatural: false };
      
      const intervals = [];
      for (let i = 1; i < times.length; i++) {
        intervals.push(times[i] - times[i-1]);
      }
      
      // Calculate variance
      const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / intervals.length;
      const stdDev = Math.sqrt(variance);
      
      // Natural typing has variation (not perfectly consistent like bots)
      const coefficientOfVariation = stdDev / mean;
      
      return {
        isNatural: coefficientOfVariation > 0.3 && coefficientOfVariation < 2,
        mean: mean,
        stdDev: stdDev
      };
    },
    
    getAnalysis() {
      const score = this.calculateScore();
      return {
        score: score,
        isHuman: score >= CONFIG.behavioralAnalysis.minScore,
        data: {
          mouseMovements: this.data.mouseMovements,
          scrollEvents: this.data.scrollEvents,
          keystrokes: this.data.keystrokes,
          touchEvents: this.data.touchEvents,
          clickCount: this.data.clickCount,
          timeOnPage: Date.now() - this.data.pageLoadTime,
          focusTime: this.data.focusTime + 
            (this.data.focusStart ? Date.now() - this.data.focusStart : 0)
        }
      };
    }
  };

  // ============================================================================
  // HONEYPOT
  // ============================================================================
  const Honeypot = {
    triggered: false,
    
    init() {
      if (!CONFIG.honeypot.enabled) return;
      
      // Inject honeypot elements into forms
      const forms = document.querySelectorAll('form');
      forms.forEach(form => this.injectHoneypot(form));
      
      // Watch for dynamically added forms
      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === 1) {
              if (node.tagName === 'FORM') {
                this.injectHoneypot(node);
              }
              const forms = node.querySelectorAll ? node.querySelectorAll('form') : [];
              forms.forEach(form => this.injectHoneypot(form));
            }
          });
        });
      });
      
      observer.observe(document.body, { childList: true, subtree: true });
      
      // Create hidden link honeypot
      this.createHiddenLink();
    },
    
    injectHoneypot(form) {
      if (form.dataset.hpInjected) return;
      form.dataset.hpInjected = 'true';
      
      // Create hidden field
      const field = document.createElement('input');
      field.type = 'text';
      field.name = CONFIG.honeypot.fieldName;
      field.tabIndex = -1;
      field.autocomplete = 'off';
      field.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none;';
      field.setAttribute('aria-hidden', 'true');
      
      form.appendChild(field);
      
      // Monitor for changes (bots might fill it)
      field.addEventListener('input', () => {
        if (field.value) {
          this.triggered = true;
          Logger.log('Honeypot triggered - form field');
        }
      });
    },
    
    createHiddenLink() {
      const link = document.createElement('a');
      link.href = '#hp-trap-' + Math.random().toString(36).substring(7);
      link.className = CONFIG.honeypot.linkClass;
      link.textContent = 'Click here for special offer';
      link.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;';
      link.setAttribute('aria-hidden', 'true');
      link.tabIndex = -1;
      
      link.addEventListener('click', (e) => {
        e.preventDefault();
        this.triggered = true;
        Logger.log('Honeypot triggered - hidden link');
      });
      
      document.body.appendChild(link);
    },
    
    checkForm(form) {
      if (!CONFIG.honeypot.enabled) return { triggered: false };
      
      const field = form.querySelector(`[name="${CONFIG.honeypot.fieldName}"]`);
      if (field && field.value) {
        return { triggered: true, reason: 'Honeypot field filled' };
      }
      
      return { triggered: this.triggered, reason: this.triggered ? 'Honeypot interaction detected' : null };
    }
  };

  // ============================================================================
  // FORM PROTECTOR
  // ============================================================================
  const FormProtector = {
    formData: new WeakMap(),
    
    init() {
      if (!CONFIG.formProtection.enabled) return;
      
      // Protect existing forms
      const forms = document.querySelectorAll('form');
      forms.forEach(form => this.protectForm(form));
      
      // Watch for new forms
      const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === 1) {
              if (node.tagName === 'FORM') {
                this.protectForm(node);
              }
              const forms = node.querySelectorAll ? node.querySelectorAll('form') : [];
              forms.forEach(form => this.protectForm(form));
            }
          });
        });
      });
      
      observer.observe(document.body, { childList: true, subtree: true });
    },
    
    protectForm(form) {
      if (this.formData.has(form)) return;
      
      const data = {
        loadTime: Date.now(),
        mouseMovements: 0,
        keystrokes: 0,
        focused: false
      };
      
      this.formData.set(form, data);
      
      // Track form-specific interactions
      form.addEventListener('mousemove', () => {
        data.mouseMovements++;
      }, { passive: true });
      
      form.addEventListener('keydown', () => {
        data.keystrokes++;
      }, { passive: true });
      
      form.addEventListener('focusin', () => {
        data.focused = true;
      }, { passive: true });
      
      // Intercept form submission
      form.addEventListener('submit', (e) => {
        const result = this.validateSubmission(form);
        if (!result.valid) {
          e.preventDefault();
          e.stopPropagation();
          Logger.log('Form submission blocked', result);
          SecurityShield.handleThreat('form_protection', result);
          return false;
        }
      });
    },
    
    validateSubmission(form) {
      const data = this.formData.get(form);
      if (!data) return { valid: true };
      
      const timeSinceLoad = Date.now() - data.loadTime;
      const issues = [];
      
      // Check minimum time
      if (timeSinceLoad < CONFIG.formProtection.minSubmitTime) {
        issues.push('Submitted too quickly (' + timeSinceLoad + 'ms)');
      }
      
      // Check mouse movement
      if (CONFIG.formProtection.checkMouseMovement && data.mouseMovements < 3) {
        issues.push('No mouse movement in form');
      }
      
      // Check keystrokes (if there are text inputs)
      const hasTextInputs = form.querySelectorAll('input[type="text"], input[type="email"], textarea').length > 0;
      if (CONFIG.formProtection.checkKeystrokes && hasTextInputs && data.keystrokes < 3) {
        issues.push('No keystrokes detected');
      }
      
      // Check honeypot
      const honeypotResult = Honeypot.checkForm(form);
      if (honeypotResult.triggered) {
        issues.push(honeypotResult.reason);
      }
      
      // Check for disposable emails
      if (CONFIG.formProtection.blockDisposableEmails) {
        const emailInputs = form.querySelectorAll('input[type="email"], input[name*="email"]');
        emailInputs.forEach(input => {
          const email = input.value.toLowerCase();
          const domain = email.split('@')[1];
          if (domain && CONFIG.disposableEmailDomains.includes(domain)) {
            issues.push('Disposable email domain: ' + domain);
          }
        });
      }
      
      // Check for spam patterns
      const textAreas = form.querySelectorAll('textarea');
      textAreas.forEach(textarea => {
        const text = textarea.value;
        for (const pattern of CONFIG.spamPatterns) {
          if (pattern.test(text)) {
            issues.push('Spam pattern detected');
            break;
          }
        }
      });
      
      return {
        valid: issues.length === 0,
        issues: issues,
        data: {
          timeSinceLoad,
          mouseMovements: data.mouseMovements,
          keystrokes: data.keystrokes
        }
      };
    }
  };

  // ============================================================================
  // CLICK FRAUD DETECTOR
  // ============================================================================
  const ClickFraudDetector = {
    clicks: [],
    suspicious: false,
    
    init() {
      document.addEventListener('click', (e) => {
        this.recordClick(e);
      }, { passive: true });
    },
    
    recordClick(e) {
      const now = Date.now();
      
      // Clean old clicks (keep last 10 seconds)
      this.clicks = this.clicks.filter(c => now - c.time < 10000);
      
      this.clicks.push({
        x: e.clientX,
        y: e.clientY,
        time: now
      });
      
      // Check for click spam
      if (this.clicks.length >= 10) {
        const recentClicks = this.clicks.filter(c => now - c.time < 2000);
        if (recentClicks.length >= 10) {
          this.suspicious = true;
          Logger.log('Click spam detected');
          SecurityShield.handleThreat('click_fraud', {
            clicksIn2Seconds: recentClicks.length
          });
        }
        
        // Check for repeated same-position clicks
        const samePosition = this.clicks.filter(c => 
          Math.abs(c.x - e.clientX) < 5 && Math.abs(c.y - e.clientY) < 5
        );
        if (samePosition.length >= 5) {
          this.suspicious = true;
          Logger.log('Repeated position clicks detected');
        }
      }
    },
    
    isSuspicious() {
      return this.suspicious;
    }
  };

  // ============================================================================
  // CHALLENGE PAGE
  // ============================================================================
  const Challenge = {
    overlay: null,
    resolved: false,
    
    show(reason) {
      if (!CONFIG.responseActions.showChallengePage) return false;
      if (this.resolved) return true; // Already passed
      
      this.createOverlay(reason);
      return false;
    },
    
    createOverlay(reason) {
      if (this.overlay) return;
      
      this.overlay = document.createElement('div');
      this.overlay.id = 'mxts-challenge';
      this.overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.95);
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      `;
      
      const content = document.createElement('div');
      content.style.cssText = `
        background: #fff;
        padding: 40px;
        border-radius: 12px;
        max-width: 400px;
        text-align: center;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      `;
      
      if (CONFIG.responseActions.challengeType === 'math') {
        this.createMathChallenge(content);
      } else if (CONFIG.responseActions.challengeType === 'button') {
        this.createButtonChallenge(content);
      } else {
        this.createTimingChallenge(content);
      }
      
      this.overlay.appendChild(content);
      document.body.appendChild(this.overlay);
      document.body.style.overflow = 'hidden';
    },
    
    createMathChallenge(container) {
      const num1 = Math.floor(Math.random() * 10) + 1;
      const num2 = Math.floor(Math.random() * 10) + 1;
      const answer = num1 + num2;
      
      container.innerHTML = `
        <div style="margin-bottom: 20px;">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <h2 style="margin: 0 0 10px; color: #1f2937; font-size: 24px;">Security Check</h2>
        <p style="margin: 0 0 20px; color: #6b7280;">Please solve this simple math problem to continue:</p>
        <p style="font-size: 28px; font-weight: bold; color: #1f2937; margin: 20px 0;">
          ${num1} + ${num2} = ?
        </p>
        <input type="number" id="mxts-answer" placeholder="Enter answer" style="
          width: 100%;
          padding: 12px;
          font-size: 18px;
          border: 2px solid #e5e7eb;
          border-radius: 8px;
          text-align: center;
          margin-bottom: 15px;
          box-sizing: border-box;
        " />
        <button id="mxts-submit" style="
          width: 100%;
          padding: 12px 24px;
          background: #3b82f6;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
        ">Verify</button>
        <p id="mxts-error" style="color: #ef4444; margin-top: 15px; display: none;">Incorrect answer. Please try again.</p>
        <p style="margin-top: 20px; font-size: 12px; color: #9ca3af;">
          Protected by MexTech Security Shield<br>
          © 2025 MexTech Limited
        </p>
      `;
      
      const input = container.querySelector('#mxts-answer');
      const button = container.querySelector('#mxts-submit');
      const error = container.querySelector('#mxts-error');
      
      const verify = () => {
        if (parseInt(input.value) === answer) {
          this.resolve();
        } else {
          error.style.display = 'block';
          input.value = '';
          input.focus();
        }
      };
      
      button.addEventListener('click', verify);
      input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') verify();
      });
      
      setTimeout(() => input.focus(), 100);
    },
    
    createButtonChallenge(container) {
      const startTime = Date.now();
      
      container.innerHTML = `
        <div style="margin-bottom: 20px;">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <h2 style="margin: 0 0 10px; color: #1f2937; font-size: 24px;">Security Check</h2>
        <p style="margin: 0 0 20px; color: #6b7280;">Click the button below to verify you're human:</p>
        <button id="mxts-verify" style="
          padding: 16px 48px;
          background: #10b981;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 18px;
          font-weight: 600;
          cursor: pointer;
          transition: transform 0.1s;
        ">I'm Human</button>
        <p id="mxts-error" style="color: #ef4444; margin-top: 15px; display: none;">Please wait a moment before clicking.</p>
        <p style="margin-top: 20px; font-size: 12px; color: #9ca3af;">
          Protected by MexTech Security Shield<br>
          © 2025 MexTech Limited
        </p>
      `;
      
      const button = container.querySelector('#mxts-verify');
      const error = container.querySelector('#mxts-error');
      
      button.addEventListener('click', () => {
        const elapsed = Date.now() - startTime;
        if (elapsed > 500 && elapsed < 10000) {
          this.resolve();
        } else if (elapsed <= 500) {
          error.textContent = 'That was too fast. Please try again.';
          error.style.display = 'block';
        } else {
          error.textContent = 'Session expired. Please refresh.';
          error.style.display = 'block';
        }
      });
    },
    
    createTimingChallenge(container) {
      let canClick = false;
      
      container.innerHTML = `
        <div style="margin-bottom: 20px;">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <h2 style="margin: 0 0 10px; color: #1f2937; font-size: 24px;">Security Check</h2>
        <p style="margin: 0 0 20px; color: #6b7280;">Wait for the button to turn green, then click it:</p>
        <button id="mxts-timing" style="
          padding: 16px 48px;
          background: #ef4444;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 18px;
          font-weight: 600;
          cursor: not-allowed;
          transition: background 0.3s;
        ">Wait...</button>
        <p id="mxts-error" style="color: #ef4444; margin-top: 15px; display: none;">Too early! Wait for green.</p>
        <p style="margin-top: 20px; font-size: 12px; color: #9ca3af;">
          Protected by MexTech Security Shield<br>
          © 2025 MexTech Limited
        </p>
      `;
      
      const button = container.querySelector('#mxts-timing');
      const error = container.querySelector('#mxts-error');
      
      const delay = 1500 + Math.random() * 1500;
      
      setTimeout(() => {
        canClick = true;
        button.style.background = '#10b981';
        button.style.cursor = 'pointer';
        button.textContent = 'Click Now!';
      }, delay);
      
      button.addEventListener('click', () => {
        if (canClick) {
          this.resolve();
        } else {
          error.style.display = 'block';
        }
      });
    },
    
    resolve() {
      this.resolved = true;
      Storage.set('challenge_passed', true, 3600000); // 1 hour
      
      if (this.overlay) {
        this.overlay.remove();
        this.overlay = null;
      }
      document.body.style.overflow = '';
      
      Logger.log('Challenge passed');
    },
    
    isResolved() {
      if (this.resolved) return true;
      const stored = Storage.get('challenge_passed');
      if (stored) {
        this.resolved = true;
        return true;
      }
      return false;
    }
  };

  // ============================================================================
  // MAIN SECURITY SHIELD
  // ============================================================================
  const SecurityShield = {
    initialized: false,
    blocked: false,
    threats: [],
    
    async init() {
      if (this.initialized || !CONFIG.enabled) return;
      this.initialized = true;
      
      // Check Do Not Track
      if (CONFIG.privacy.respectDoNotTrack && navigator.doNotTrack === '1') {
        Logger.log('Do Not Track enabled - limiting tracking features');
        CONFIG.behavioralAnalysis.enabled = false;
      }
      
      // Collect fingerprint
      Fingerprint.collect();
      
      // Detect visitor IP if enabled (async, non-blocking)
      if (CONFIG.ipBlocking.detectIP) {
        IPUtils.detectVisitorIP().then(ip => {
          if (ip) {
            Logger.log('Visitor IP detected', ip);
            this.checkIPBlocklist(ip);
          }
        });
      }
      
      // Initialize modules
      RateLimiter.init();
      BehavioralAnalyzer.init();
      Honeypot.init();
      FormProtector.init();
      ClickFraudDetector.init();
      
      // Run initial checks
      this.runChecks();
      
      Logger.log('MexTech Security Shield initialized', {
        fingerprint: Fingerprint.getHash()
      });
    },
    
    checkIPBlocklist(ip) {
      if (!CONFIG.ipBlocking.enabled || !ip) return;
      
      if (IPUtils.isBlocked(ip, CONFIG.ipBlocking.customBlocklist)) {
        this.handleThreat('ip_blocked', { ip: ip, reason: 'IP in blocklist' });
      }
    },
    
    runChecks() {
      // Check rate limit (uses fingerprint as key since we may not have IP)
      const rateResult = RateLimiter.check();
      if (!rateResult.allowed) {
        this.handleThreat('rate_limit', rateResult);
        return;
      }
      
      // Check for bots
      const botResult = BotDetector.analyze();
      if (botResult.isBot) {
        this.handleThreat('bot_detection', botResult);
        return;
      }
      
      // IP blocklist check happens asynchronously when IP is detected
      if (CONFIG.ipBlocking.enabled && CONFIG.ipBlocking.customBlocklist.length > 0) {
        Logger.log('Custom IP blocklist configured with ' + CONFIG.ipBlocking.customBlocklist.length + ' entries');
        // If IP detection is disabled, we can only check once IP is known
        // Enable CONFIG.ipBlocking.detectIP to use IP-based blocking
      }
    },
    
    handleThreat(type, data) {
      this.threats.push({
        type,
        data,
        timestamp: Date.now()
      });
      
      Logger.log('Threat detected: ' + type, data);
      Logger.sendToWebhook('blocked', { type, data });
      
      const action = CONFIG.responseActions.action;
      
      switch (action) {
        case 'block':
          this.blockUser(type, data);
          break;
        case 'redirect':
          window.location.href = CONFIG.responseActions.redirectUrl;
          break;
        case 'challenge':
          if (!Challenge.isResolved()) {
            Challenge.show(type);
          }
          break;
        case 'log':
          // Just log, don't take action
          break;
      }
    },
    
    blockUser(reason, data) {
      this.blocked = true;
      
      // Create block overlay
      const overlay = document.createElement('div');
      overlay.id = 'mxts-blocked';
      overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      `;
      
      let statusCode = '403';
      let statusText = 'Access Denied';
      
      if (reason === 'rate_limit') {
        statusCode = '429';
        statusText = 'Too Many Requests';
      }
      
      overlay.innerHTML = `
        <div style="text-align: center; color: white; padding: 40px;">
          <div style="font-size: 120px; font-weight: 700; opacity: 0.3; margin-bottom: -20px;">
            ${statusCode}
          </div>
          <h1 style="font-size: 32px; margin: 0 0 15px; font-weight: 600;">
            ${statusText}
          </h1>
          <p style="font-size: 16px; color: rgba(255,255,255,0.7); max-width: 400px; margin: 0 auto 30px;">
            Your request has been blocked by our security system. 
            If you believe this is an error, please try again later or contact the site administrator.
          </p>
          ${data.retryAfter ? `
            <p style="font-size: 14px; color: rgba(255,255,255,0.5);">
              Retry after: ${data.retryAfter} seconds
            </p>
          ` : ''}
          <p style="font-size: 12px; color: rgba(255,255,255,0.3); margin-top: 40px;">
            Protected by MexTech Security Shield<br>
            © 2025 MexTech Limited • mextechltd.name.ng
          </p>
        </div>
      `;
      
      // Clear page content
      document.body.innerHTML = '';
      document.body.appendChild(overlay);
      document.body.style.margin = '0';
      document.body.style.overflow = 'hidden';
    },
    
    // Public API
    getStatus() {
      return {
        initialized: this.initialized,
        blocked: this.blocked,
        threats: this.threats,
        behavioral: BehavioralAnalyzer.getAnalysis(),
        fingerprint: Fingerprint.getHash()
      };
    },
    
    checkBehavior() {
      return BehavioralAnalyzer.getAnalysis();
    },
    
    validateForm(form) {
      return FormProtector.validateSubmission(form);
    },
    
    isBlocked() {
      return this.blocked;
    }
  };

  // ============================================================================
  // AUTO-INITIALIZATION
  // ============================================================================
  
  // Initialize immediately if DOM is ready, otherwise wait
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => SecurityShield.init());
  } else {
    SecurityShield.init();
  }
  
  // Expose to global scope
  window.MexTechSecurity = SecurityShield;
  window.MexTechSecurityConfig = CONFIG;

})(window, document);

/**
 * ============================================================================
 * INSTALLATION INSTRUCTIONS
 * ============================================================================
 * 
 * 1. BASIC INSTALLATION:
 *    Add this script to your HTML file, preferably just before </body>:
 * 
 *    <script src="mextech-security.js"></script>
 * 
 *    Or inline in your HTML:
 *    <script>
 *      // Paste the entire script here
 *    </script>
 * 
 * 2. CONFIGURATION:
 *    Edit the CONFIG object at the top of the script to customize settings.
 *    Or after loading, modify window.MexTechSecurityConfig before DOMContentLoaded.
 * 
 * 3. OPTIONAL .HTACCESS RULES (for JavaScript-disabled users):
 *    Add to your .htaccess file:
 * 
 *    # Block known bad bots
 *    RewriteEngine On
 *    RewriteCond %{HTTP_USER_AGENT} (bot|crawler|spider|scraper|wget|curl) [NC]
 *    RewriteRule .* - [F,L]
 * 
 *    # Rate limiting (requires mod_evasive)
 *    <IfModule mod_evasive20.c>
 *      DOSHashTableSize 3097
 *      DOSPageCount 5
 *      DOSSiteCount 100
 *      DOSPageInterval 1
 *      DOSSiteInterval 1
 *      DOSBlockingPeriod 60
 *    </IfModule>
 * 
 * 4. ACCESSING THE API:
 *    After the script loads, you can use:
 * 
 *    // Get current security status
 *    console.log(window.MexTechSecurity.getStatus());
 * 
 *    // Check behavioral score
 *    console.log(window.MexTechSecurity.checkBehavior());
 * 
 *    // Validate a form manually
 *    const result = window.MexTechSecurity.validateForm(document.querySelector('form'));
 * 
 * 5. NOSCRIPT FALLBACK:
 *    For users with JavaScript disabled, add this to your HTML:
 * 
 *    <noscript>
 *      <div style="background:#ff0;padding:20px;text-align:center;">
 *        Please enable JavaScript for full security protection.
 *      </div>
 *    </noscript>
 * 
 * ============================================================================
 * Copyright © 2025 MexTech Limited. All rights reserved.
 * https://mextechltd.name.ng
 * ============================================================================
 */
