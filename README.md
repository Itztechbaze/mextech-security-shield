# MexTech Security Shield v1.0.0

**A production-ready, single-file JavaScript security script for static HTML websites.**

Protect your site against attacks, spam, bots, scams, malware distribution, and phishing attempts with zero configuration.

---

## 🚀 Features

### IP Blocking
- Custom blocklist with CIDR notation support (`1.2.3.4`, `5.6.7.0/24`)
- Optional IP detection via free ipify API
- 24-hour cache for performance
- Configurable response actions per blocked IP

### Bot Detection
- WebDriver/Selenium detection
- Headless browser detection (Phantom, Puppeteer, Playwright, etc.)
- User-Agent analysis with 40+ bad bot patterns
- Plugin verification
- Language configuration checking
- JavaScript execution verification

### Honeypot Traps
- Invisible form fields to catch bot submissions
- Hidden links that bots are likely to click
- Tab-index manipulation for visibility control
- CSS-hidden elements with proper ARIA attributes

### Rate Limiting
- Configurable per-visitor request limits (default: 60 requests/minute)
- Burst allowance (default: 10 extra requests)
- Automatic blocking with retry-after timing
- Fingerprint-based limiting (no server needed)
- Block duration: 5 minutes (configurable)

### Form Protection
- Minimum submission time enforcement (default: 2 seconds)
- Honeypot field validation
- Disposable email domain blocking (40+ domains)
- Spam pattern detection (40+ patterns)
- Mouse movement verification
- Keystroke activity detection
- Form interaction tracking

### Behavioral Analysis
- Mouse movement tracking and variance analysis
- Scroll event tracking
- Keystroke timing analysis with rhythm verification
- Touch event detection
- Page focus time tracking
- Natural user interaction scoring (0-100 scale)
- Configurable human threshold (default: 30/100)

### Phishing & Click Fraud Detection
- Click position variance analysis
- Rapid click detection (10+ clicks in 2 seconds)
- Repeated position clicking detection
- Geographic/behavioral inconsistency tracking

### Response Actions
- **Block**: Show access denied overlay with custom message
- **Redirect**: Redirect to maintenance or error page
- **Challenge**: Math problem, button verification, or timing-based challenge
- **Log**: Silent logging without blocking (webhook integration)

### Privacy-Respecting
- Automatic DNT (Do Not Track) detection
- Disables behavioral tracking when DNT enabled
- Client-side only processing
- localStorage-based data (no external transmission except webhooks)
- No cookie injection
- No external analytics

---

## 📦 Installation

### Method 1: Direct Script Tag
```html
<script src="mextech-security.min.js"></script>
```

### Method 2: Full Version (Development)
```html
<script src="mextech-security.js"></script>
```

### Method 3: CDN (when hosted)
```html
<script src="https://your-cdn.com/mextech-security.min.js"></script>
```

**That's it!** The script initializes automatically on page load.

---

## 📊 File Specifications

| File | Size | Use Case |
|------|------|----------|
| mextech-security.js | ~37KB | Development (readable, commented) |
| mextech-security.min.js | 24.95KB | Production (minified, optimized) |

Both files are identical in functionality. Use the minified version in production to stay under bandwidth limits.

---

## ⚙️ Configuration

The script works with **zero configuration**, but you can customize protection levels:

### Basic Configuration
```javascript
// Enable/disable entire security system
MexTechSecurityConfig.enabled = true;

// Enable debug logging to console
MexTechSecurityConfig.debug = false;
```

### Bot Detection Configuration
```javascript
MexTechSecurityConfig.botDetection.enabled = true;
MexTechSecurityConfig.botDetection.blockHeadlessBrowsers = true;
MexTechSecurityConfig.botDetection.blockBadUserAgents = true;
MexTechSecurityConfig.botDetection.checkWebDriver = true;
MexTechSecurityConfig.botDetection.checkPlugins = true;
MexTechSecurityConfig.botDetection.checkLanguages = true;
```

### Rate Limiting Configuration
```javascript
MexTechSecurityConfig.rateLimiting.enabled = true;
MexTechSecurityConfig.rateLimiting.maxRequests = 60;        // per window
MexTechSecurityConfig.rateLimiting.windowMs = 60000;        // 1 minute
MexTechSecurityConfig.rateLimiting.burstAllowed = 10;       // extra requests
MexTechSecurityConfig.rateLimiting.blockDuration = 300000;  // 5 minutes
```

### Form Protection Configuration
```javascript
MexTechSecurityConfig.formProtection.enabled = true;
MexTechSecurityConfig.formProtection.minSubmitTime = 2000;          // 2 seconds
MexTechSecurityConfig.formProtection.checkMouseMovement = true;
MexTechSecurityConfig.formProtection.checkKeystrokes = true;
MexTechSecurityConfig.formProtection.blockDisposableEmails = true;
```

### Behavioral Analysis Configuration
```javascript
MexTechSecurityConfig.behavioralAnalysis.enabled = true;
MexTechSecurityConfig.behavioralAnalysis.minScore = 30;           // 0-100 scale
MexTechSecurityConfig.behavioralAnalysis.trackMouseMovement = true;
MexTechSecurityConfig.behavioralAnalysis.trackScrolling = true;
MexTechSecurityConfig.behavioralAnalysis.trackKeystrokes = true;
MexTechSecurityConfig.behavioralAnalysis.trackTouchEvents = true;
MexTechSecurityConfig.behavioralAnalysis.trackFocusTime = true;
```

### IP Blocking Configuration
```javascript
MexTechSecurityConfig.ipBlocking.enabled = true;

// Add custom blocklist
MexTechSecurityConfig.ipBlocking.customBlocklist = [
  "192.168.1.100",
  "10.0.0.0/8",
  "172.16.0.0/12"
];

// Enable IP detection (makes external API call)
MexTechSecurityConfig.ipBlocking.detectIP = true;
MexTechSecurityConfig.ipBlocking.ipApiUrl = "https://api.ipify.org?format=json";
```

### Response Actions Configuration
```javascript
MexTechSecurityConfig.responseActions.action = "block";  // "block", "redirect", "challenge", "log"

// For redirect action:
MexTechSecurityConfig.responseActions.redirectUrl = "/maintenance.html";

// For challenge action:
MexTechSecurityConfig.responseActions.showChallengePage = true;
MexTechSecurityConfig.responseActions.challengeType = "math";  // "math", "button", "timing"
```

### Webhook Configuration (Receive Notifications)
```javascript
MexTechSecurityConfig.webhook.enabled = true;
MexTechSecurityConfig.webhook.url = "https://your-server.com/api/security-events";
MexTechSecurityConfig.webhook.sendBlocked = true;
MexTechSecurityConfig.webhook.sendSuspicious = true;

// Webhook payload:
// {
//   type: "blocked",
//   timestamp: "2025-11-26T10:30:00.000Z",
//   url: "https://example.com/page",
//   userAgent: "Mozilla/5.0...",
//   data: { /* threat details */ }
// }
```

### Privacy Configuration
```javascript
MexTechSecurityConfig.privacy.respectDoNotTrack = true;      // Auto-disable tracking if DNT enabled
MexTechSecurityConfig.privacy.noLegitUserTracking = true;    // Don't track humans
```

---

## 🔧 API Reference

### MexTechSecurity Object

#### Get Security Status
```javascript
const status = MexTechSecurity.getStatus();

// Returns:
// {
//   initialized: boolean,
//   blocked: boolean,
//   threats: Array,
//   behavioral: { score, isHuman, data },
//   fingerprint: string,
//   visitorIP: string | null
// }
```

#### Check Behavioral Score
```javascript
const analysis = MexTechSecurity.checkBehavior();

// Returns:
// {
//   score: 0-100,
//   isHuman: boolean,
//   data: {
//     mouseMovements: number,
//     scrollEvents: number,
//     keystrokes: number,
//     touchEvents: number,
//     clickCount: number,
//     timeOnPage: number,
//     focusTime: number
//   }
// }
```

#### Validate Form Before Submission
```javascript
const validation = MexTechSecurity.validateForm(formElement);

// Returns:
// {
//   valid: boolean,
//   issues: Array,
//   data: {
//     timeSinceLoad: number,
//     mouseMovements: number,
//     keystrokes: number
//   }
// }
```

#### Check If Visitor Is Blocked
```javascript
const blocked = MexTechSecurity.isBlocked();
// Returns: true | false
```

#### Access Global Configuration
```javascript
// Read current config
const currentThreshold = MexTechSecurityConfig.behavioralAnalysis.minScore;

// Modify config at runtime
MexTechSecurityConfig.rateLimiting.maxRequests = 100;
```

---

## 🛡️ How It Works

### Detection Pipeline

1. **Initial Fingerprinting**
   - Collects user agent, screen info, plugins, timezone, etc.
   - Generates unique visitor fingerprint
   - Cached for rate limiting

2. **Bot Detection Analysis**
   - Checks WebDriver presence
   - Detects headless browsers
   - Analyzes user agent against 40+ bot patterns
   - Verifies browser plugins and languages
   - Scores likelihood of bot (0-100)

3. **Rate Limiting Check**
   - Tracks requests per fingerprint
   - Checks against configured limits
   - Detects bursts
   - Auto-blocks if threshold exceeded

4. **Form Interaction Monitoring**
   - Tracks mouse movements in forms
   - Monitors keystrokes
   - Records submission time
   - Checks honeypot fields
   - Validates email domains

5. **Behavioral Analysis**
   - Analyzes mouse movement patterns
   - Calculates typing rhythm
   - Measures page engagement
   - Scores as human (30+) or bot (<30)

6. **Action Execution**
   - Blocks user with overlay
   - Redirects to maintenance page
   - Shows challenge (math, button, timing)
   - Sends webhook notification

### Scoring System

**Behavioral Analysis Score (0-100)**
- Mouse movements: +25 max
- Scroll events: +15 max
- Keystrokes: +15 max
- Touch events: +15 max
- Page load time: +15 max
- Focus time: +10 max
- Click count: +10 max

**Bot Detection Score (0-100)**
- WebDriver detected: -80
- Headless browser: -70
- Bad user agent: -60
- No plugins (desktop): -20
- No languages: -30

---

## 🔐 Security Considerations

### What It Protects
✅ Stops automated form submissions
✅ Blocks known bot user agents
✅ Prevents click fraud
✅ Detects unnatural behavior patterns
✅ Blocks rate limit abuse
✅ Catches spam submissions

### What It Doesn't (By Design)
❌ Prevent DDoS attacks (too large scale)
❌ Block VPN/Proxy users (user choice)
❌ Verify user identity (use auth for that)
❌ Prevent SQL injection (server-side concern)
❌ Monitor HTTPS traffic (browser limitation)

### Client-Side Limitations
- Clever attackers can spoof metrics
- Determined bots may bypass some checks
- Fingerprinting can be mimicked
- IP blocking requires server-side verification for real enforcement

**Recommendation:** Use as first-line defense, complement with server-side validation for critical operations.

---

## 🌐 Browser Support

| Browser | Support | Notes |
|---------|---------|-------|
| Chrome 90+ | ✅ Full | All features |
| Firefox 88+ | ✅ Full | All features |
| Safari 14+ | ✅ Full | All features |
| Edge 90+ | ✅ Full | All features |
| Mobile Browsers | ✅ Full | Touch events supported |
| IE 11 | ⚠️ Partial | Missing some modern APIs |

---

## 📋 Challenge Types

### Math Challenge
User solves a simple math problem (e.g., "What is 5 + 3?")
- Best for: General protection
- Difficulty: Easy
- Time to pass: ~10-30 seconds

### Button Challenge
User waits for button to turn green then clicks it
- Best for: Timing verification
- Difficulty: Easy
- Time to pass: ~3-5 seconds

### Timing Challenge
User clicks button within specific time window
- Best for: Behavioral verification
- Difficulty: Medium
- Time to pass: ~5-10 seconds

---

## 🔗 Webhook Integration

Send detected threats to your server:

```javascript
MexTechSecurityConfig.webhook.enabled = true;
MexTechSecurityConfig.webhook.url = "https://your-api.com/security-events";
```

**Webhook Payload Example:**
```json
{
  "type": "blocked",
  "timestamp": "2025-11-26T10:30:45.123Z",
  "url": "https://example.com/contact",
  "userAgent": "Mozilla/5.0...",
  "data": {
    "type": "bot_detection",
    "data": {
      "isBot": true,
      "score": 15,
      "reasons": ["WebDriver detected", "No browser plugins"]
    }
  }
}
```

---

## 📝 Examples

### Protect Contact Form
```html
<form id="contact-form">
  <input type="text" name="name" placeholder="Your Name">
  <input type="email" name="email" placeholder="Your Email">
  <textarea name="message" placeholder="Your Message"></textarea>
  <button type="submit">Send Message</button>
</form>

<script src="mextech-security.min.js"></script>
<script>
MexTechSecurityConfig.formProtection.blockDisposableEmails = true;
MexTechSecurityConfig.responseActions.action = "challenge";
MexTechSecurityConfig.responseActions.challengeType = "math";
</script>
```

### Block Specific Countries/IPs
```javascript
<script src="mextech-security.min.js"></script>
<script>
// Block known bad IP ranges
MexTechSecurityConfig.ipBlocking.customBlocklist = [
  "203.0.113.0/24",      // Hypothetical malicious range
  "198.51.100.50",       // Specific IP
  "192.0.2.0/24"         // Another range
];

MexTechSecurityConfig.ipBlocking.detectIP = true;
</script>
```

### Strict Mode (Block Everything Suspicious)
```javascript
<script src="mextech-security.min.js"></script>
<script>
MexTechSecurityConfig.botDetection.blockHeadlessBrowsers = true;
MexTechSecurityConfig.behavioralAnalysis.minScore = 50;  // Higher threshold
MexTechSecurityConfig.rateLimiting.maxRequests = 30;     // Lower limit
MexTechSecurityConfig.formProtection.minSubmitTime = 5000; // 5 seconds

MexTechSecurityConfig.responseActions.action = "block";
</script>
```

### Logging Mode (No Blocking)
```javascript
<script src="mextech-security.min.js"></script>
<script>
MexTechSecurityConfig.responseActions.action = "log";
MexTechSecurityConfig.webhook.enabled = true;
MexTechSecurityConfig.webhook.url = "https://your-server.com/api/threats";
MexTechSecurityConfig.debug = true;  // See console logs
</script>
```

---

## 🐛 Debugging

Enable console logging:
```javascript
MexTechSecurityConfig.debug = true;
```

Check browser console for messages like:
```
[MexTech Security] Bot detected: WebDriver present
[MexTech Security] Rate limit exceeded: 67 requests in 60 seconds
[MexTech Security] Honeypot triggered - form field
[MexTech Security] Visitor IP detected: 192.0.2.1
```

---

## 📚 Best Practices

1. **Use Minified Version in Production**
   - Smaller file size (24.95KB)
   - Better performance
   - Obfuscated for security

2. **Test Challenge Types**
   - Choose one that fits your users
   - Test on mobile devices
   - Ensure accessibility

3. **Monitor Webhooks**
   - Log all security events
   - Analyze patterns over time
   - Adjust thresholds based on data

4. **Combine with Server-Side Validation**
   - Never trust client-side checks alone
   - Re-validate critical data server-side
   - Use rate limiting on server

5. **Respect User Privacy**
   - Keep DNT respect enabled
   - Don't track legitimate users
   - Be transparent about protection

6. **Update Blocklists Regularly**
   - Monitor new bot user agents
   - Update IP blocklist monthly
   - Review disposable email list

---

## 🆘 Troubleshooting

### Script Not Loading
- Check browser console for errors
- Verify script file path is correct
- Check file permissions
- Ensure CORS headers are correct

### All Visitors Getting Blocked
- Lower `behavioralAnalysis.minScore`
- Increase `rateLimiting.maxRequests`
- Disable `botDetection.checkWebDriver` if testing
- Check for DNT header interfering

### Forms Not Submitting
- Check `formProtection.minSubmitTime`
- Verify `honeypot.fieldName` not used in your form
- Check browser console for validation errors
- Review `validateForm()` API

### High False Positives
- Increase behavioral score threshold
- Disable optional bot checks
- Review webhook events for patterns
- Whitelist legitimate IPs

---

## 📞 Support

**Website:** https://mextechltd.name.ng

**Issues & Feedback:** Contact MexTech Limited support

---

## 📄 License

**Copyright © 2025 MexTech Limited. All rights reserved.**

Proprietary software. Unauthorized copying, modification, or distribution is prohibited.

Use in compliance with applicable laws and regulations.

---

## 🙏 Credits

Built with attention to security, privacy, and user experience.

**Version:** 1.0.0
**Last Updated:** November 2025
**Status:** Production Ready

---

**Protect your website. Block the threats. Respect your users.**
