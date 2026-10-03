const express = require('express');
const request = require('request');
const cheerio = require('cheerio');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const CryptoJS = require('crypto-js');

// pip installs (requests, bs4, pytesseract, Pillow) go into ./pylibs at build time
// (see railpack.json) since the mise-managed Python's own site-packages don't
// reliably survive into the deploy image. Point python3 at that folder explicitly.
const PY_ENV = {
  ...process.env,
  PYTHONPATH: path.join(__dirname, 'pylibs') + (process.env.PYTHONPATH ? `:${process.env.PYTHONPATH}` : '')
};

const app = express();
const PORT = process.env.PORT || 3000; // Railway fix

const ENCRYPTION_KEY = "nic@impds#dedup05613";

let currentJSESSIONID = null;
let currentPDSSESSIONID = null; // may differ from JSESSIONID — don't assume they're the same
let sessionLastUpdated = null;
let isRefreshingSession = false;
let sessionRefreshQueue = [];

// session.txt format: line 1 = JSESSIONID, line 2 (optional) = PDS_SESSION_ID.
// If line 2 is missing/blank, falls back to using the JSESSIONID value for both.
function readSessionFile() {
  const raw = fs.readFileSync('session.txt', 'utf8');
  const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);
  const jsessionid = lines[0] || '';
  const pdsSessionId = lines[1] || jsessionid;
  return { jsessionid, pdsSessionId };
}

function encryptAadhaar(text) {
    return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
}

function decryptAadhaar(encryptedText) {
    const bytes = CryptoJS.AES.decrypt(encryptedText, ENCRYPTION_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
}

function getFreshJSESSIONID(maxRetries = 5, retryDelay = 3000) {
  return new Promise((resolve, reject) => {
    console.log('🔄 Getting fresh JSESSIONID...');

    const attemptLogin = (retryCount = 0) => {
      const pythonProcess = spawn('python3', ['impds_auth.py'], { env: PY_ENV });

      let stdout = '';
      let stderr = '';
      let timedOut = false;

      // Safety net — agar python kisi wajah se hang ho jaye (e.g. OCR/captcha stuck),
      // isse process ko force-kill karke retry chain aage badhti rahegi.
      const killTimer = setTimeout(() => {
        timedOut = true;
        console.log('⏱️ python3 impds_auth.py timed out, killing process...');
        pythonProcess.kill('SIGKILL');
      }, 45000);

      // ERROR HANDLER — python3 not found ya file missing hone pe crash nahi hoga
      pythonProcess.on('error', (spawnErr) => {
        clearTimeout(killTimer);
        console.log('⚠️ python3 spawn failed:', spawnErr.message);
        // session.txt fallback
        try {
          if (fs.existsSync('session.txt')) {
            const { jsessionid, pdsSessionId } = readSessionFile();
            if (jsessionid && jsessionid.length > 10) {
              currentJSESSIONID = jsessionid;
              currentPDSSESSIONID = pdsSessionId;
              sessionLastUpdated = new Date();
              console.log(`✅ JSESSIONID from file: ${currentJSESSIONID}`);
              return resolve(currentJSESSIONID);
            }
          }
        } catch (e) {
          console.error('session.txt read error:', e);
        }
        if (retryCount < maxRetries) {
          console.log(`🔄 Retrying in ${retryDelay/1000}s... (${retryCount + 1}/${maxRetries})`);
          setTimeout(() => attemptLogin(retryCount + 1), retryDelay);
        } else {
          reject(new Error('python3 not available and no valid session.txt'));
        }
      });

      pythonProcess.stdout.on('data', (data) => {
        stdout += data.toString();
        console.log(data.toString().trim());
      });

      pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString();
        console.error('Python Error:', data.toString());
      });

      pythonProcess.on('close', (code) => {
        clearTimeout(killTimer);
        if (timedOut) {
          console.log('⚠️ python3 process was killed due to timeout');
        }
        const jsessionMatch = stdout.match(/\[\+\] JSESSIONID: ([A-F0-9]+)/);
        if (jsessionMatch && jsessionMatch[1]) {
          currentJSESSIONID = jsessionMatch[1];
          const pdsMatch = stdout.match(/PDS_SESSION_ID \(distinct!\): ([A-F0-9]+)/);
          currentPDSSESSIONID = pdsMatch ? pdsMatch[1] : currentJSESSIONID;
          sessionLastUpdated = new Date();
          console.log(`✅ New JSESSIONID obtained: ${currentJSESSIONID}${pdsMatch ? ` (distinct PDS_SESSION_ID: ${currentPDSSESSIONID})` : ''}`);
          resolve(currentJSESSIONID);
          return;
        }

        try {
          if (fs.existsSync('session.txt')) {
            const { jsessionid, pdsSessionId } = readSessionFile();
            if (jsessionid && jsessionid.length > 10) {
              currentJSESSIONID = jsessionid;
              currentPDSSESSIONID = pdsSessionId;
              sessionLastUpdated = new Date();
              console.log(`✅ JSESSIONID from file: ${currentJSESSIONID}`);
              resolve(currentJSESSIONID);
              return;
            }
          }
        } catch (error) {
          console.error('Error reading session file:', error);
        }

        if (retryCount < maxRetries) {
          console.log(`🔄 Login failed, retrying in ${retryDelay/1000} seconds... (${retryCount + 1}/${maxRetries})`);
          setTimeout(() => attemptLogin(retryCount + 1), retryDelay);
        } else {
          reject(new Error(`Failed to get JSESSIONID after ${maxRetries} attempts: ${stderr || 'Login failed'}`));
        }
      });
    };

    attemptLogin();
  });
}

function needsSessionRefresh() {
  if (!currentJSESSIONID || !sessionLastUpdated) return true;
  const now = new Date();
  const diffMinutes = (now - sessionLastUpdated) / (1000 * 60);
  return diffMinutes > 30;
}

async function ensureValidSession() {
  if (isRefreshingSession) {
    return new Promise((resolve) => {
      sessionRefreshQueue.push(resolve);
    });
  }

  if (needsSessionRefresh()) {
    isRefreshingSession = true;
    console.log('🔄 Session needs refresh, getting new JSESSIONID...');

    try {
      await getFreshJSESSIONID();
      console.log('✅ Session refreshed successfully');

      while (sessionRefreshQueue.length > 0) {
        const resolve = sessionRefreshQueue.shift();
        resolve();
      }
    } catch (error) {
      console.error('❌ Failed to refresh session:', error);

      while (sessionRefreshQueue.length > 0) {
        const resolve = sessionRefreshQueue.shift();
        resolve();
      }
      throw error;
    } finally {
      isRefreshingSession = false;
    }
  }
}

function parseSearchResults(html) {
  const $ = cheerio.load(html);
  const results = [];

  const tables = $('table.table-striped.table-bordered.table-hover');

  if (tables.length < 2) {
    return { error: 'No valid data found in response' };
  }

  const mainTable = tables.first();
  const rows = mainTable.find('tbody tr');

  if (rows.length === 0) {
    return { error: 'No records found' };
  }

  const rationCardMap = {};

  rows.each((index, row) => {
    const tds = $(row).find('td');

    if (tds.length >= 8) {
      const rationCardNo = $(tds[3]).text().trim();

      if (!rationCardMap[rationCardNo]) {
        rationCardMap[rationCardNo] = {
          ration_card_details: {
            state_name: $(tds[1]).text().trim(),
            district_name: $(tds[2]).text().trim(),
            ration_card_no: rationCardNo,
            scheme_name: $(tds[4]).text().trim()
          },
          members: []
        };
      }

      rationCardMap[rationCardNo].members.push({
        s_no: parseInt($(tds[0]).text().trim()),
        member_id: $(tds[5]).text().trim(),
        member_name: $(tds[6]).text().trim(),
        remark: $(tds[7]).text().trim() || null
      });
    }
  });

  const finalResults = Object.values(rationCardMap).map(card => {
    const additionalInfoTable = tables.eq(1);
    card.additional_info = parseAdditionalInfo(additionalInfoTable);
    return card;
  });

  return finalResults;
}

function parseAdditionalInfo(table) {
  const $ = cheerio.load(table.html());
  const info = {
    fps_category: "Unknown",
    impds_transaction_allowed: false,
    exists_in_central_repository: false,
    duplicate_aadhaar_beneficiary: false
  };

  const rows = table.find('tbody tr');

  rows.each((index, row) => {
    const tds = $(row).find('td');
    if (tds.length >= 2) {
      const label = $(tds[0]).text().trim();
      const value = $(tds[1]).text().trim().toLowerCase();

      if (label.includes('FPS category')) {
        info.fps_category = value === 'yes' ? 'Online FPS' : 'Offline FPS';
      } else if (label.includes('IMPDS transaction')) {
        info.impds_transaction_allowed = value === 'yes';
      } else if (label.includes('Central Repository')) {
        info.exists_in_central_repository = value === 'yes';
      } else if (label.includes('duplicate Aadaar')) {
        info.duplicate_aadhaar_beneficiary = value === 'yes';
      }
    }
  });

  return info;
}

// The search page embeds a fresh, single-use REQ_CSRF_TOKEN hidden input that
// must be submitted along with the search form, same as the login page does.
// Without it the server throws a generic 500 (not actually a session issue).
function fetchSearchPageCsrfToken(callback) {
  request.get({
    url: 'https://impds.nic.in/impdsdeduplication/search',
    headers: {
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      'Cookie': `JSESSIONID=${currentJSESSIONID}; PDS_SESSION_ID=${currentPDSSESSIONID || currentJSESSIONID}`
    },
    timeout: 15000
  }, (err, response, body) => {
    if (err) return callback(err, null);
    const $ = cheerio.load(body || '');
    let token = $('input[name="REQ_CSRF_TOKEN"]').attr('value');

    // Fall back to common Spring Security meta-tag pattern if the hidden
    // input isn't present on this particular page.
    if (!token) {
      token = $('meta[name="_csrf"]').attr('content') || $('meta[name="csrf-token"]').attr('content');
    }

    if (!token) {
      console.log(`🧪 CSRF diagnostic — GET ${response.statusCode}, final url: ${response.request && response.request.href}`);
      console.log(`🧪 CSRF diagnostic — body snippet: ${(body || '').substring(0, 500).replace(/\s+/g, ' ')}`);
      return callback(new Error('Could not find REQ_CSRF_TOKEN on search page'), null);
    }
    callback(null, token);
  });
}

function makeAadhaarSearchRequest(searchTerm, encryptedAadhaar, callback) {
  const attemptRequest = async (retryCount = 0) => {
    const maxRetries = 3;

    // Per request: always log in fresh for every single Aadhaar search,
    // instead of reusing/caching a session across requests.
    try {
      console.log('🔄 Forcing fresh login for this request (no session reuse)...');
      await getFreshJSESSIONID();
    } catch (error) {
      return callback(error, null, null);
    }

    let csrfToken;
    try {
      csrfToken = await new Promise((resolve, reject) => {
        fetchSearchPageCsrfToken((err, token) => err ? reject(err) : resolve(token));
      });
    } catch (csrfErr) {
      console.log(`⚠️ Could not fetch search-page CSRF token: ${csrfErr.message}`);
      if (retryCount < maxRetries) {
        sessionLastUpdated = null;
        setTimeout(() => attemptRequest(retryCount + 1), 2000);
        return;
      }
      return callback(csrfErr, null, null);
    }

    const formData = {
      'search': searchTerm,
      'aadhar': encryptedAadhaar,
      'REQ_CSRF_TOKEN': csrfToken
    };

    request.post({
      url: 'https://impds.nic.in/impdsdeduplication/search',
      headers: {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Content-Type': 'application/x-www-form-urlencoded',
        'cache-control': 'max-age=0',
        'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Linux"',
        'origin': 'https://impds.nic.in',
        'upgrade-insecure-requests': '1',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-user': '?1',
        'sec-fetch-dest': 'document',
        'referer': 'https://impds.nic.in/impdsdeduplication/search',
        'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6,zh-CN;q=0.5,zh;q=0.4,de;q=0.3',
        'priority': 'u=0, i',
        'Cookie': `JSESSIONID=${currentJSESSIONID}; PDS_SESSION_ID=${currentPDSSESSIONID || currentJSESSIONID}`
      },
      form: formData,
      timeout: 30000
    }, (err, response, body) => {
      if (err) {
        console.error('Aadhaar search request error:', err);
        return callback(err, null, null);
      }

      const isSessionExpired = response.statusCode === 500 ||
          (body && (body.includes('Login Page') ||
                   body.includes('UserLogin') ||
                   body.includes('REQ_CSRF_TOKEN')));

      if (isSessionExpired) {
        console.log('🔐 Session expired detected in Aadhaar search');
        console.log(`🧪 Diagnostic — status=${response.statusCode}, body snippet: ${(body || '').substring(0, 300).replace(/\s+/g, ' ')}`);

        if (retryCount < maxRetries) {
          sessionLastUpdated = null;
          console.log(`🔄 Retrying Aadhaar search with fresh session... (${retryCount + 1}/${maxRetries})`);

          setTimeout(() => {
            attemptRequest(retryCount + 1);
          }, 2000);
          return;
        } else {
          return callback(new Error('Max retries exceeded for session refresh in Aadhaar search'), null, null);
        }
      }

      if (response.statusCode !== 200) {
        return callback(new Error(`HTTP ${response.statusCode}: ${body}`), null, null);
      }

      callback(null, response, body);
    });
  };

  attemptRequest();
}

app.get('/search-aadhaar', (req, res) => {
  const search = req.query.search || 'A';
  const aadhaar = req.query.aadhaar;

  if (!aadhaar) {
    return res.status(400).json({
      success: false,
      error: 'Missing aadhaar parameter'
    });
  }

  console.log(`🔍 Aadhaar search request: search="${search}", aadhaar="${aadhaar.substring(0, 10)}..."`);

  let encryptedAadhaar;
  try {
    const decrypted = decryptAadhaar(aadhaar);
    if (decrypted && decrypted.length > 0) {
      encryptedAadhaar = aadhaar;
      console.log('✅ Using already encrypted Aadhaar');
    } else {
      encryptedAadhaar = encryptAadhaar(aadhaar);
      console.log('🔐 Encrypted Aadhaar for request');
    }
  } catch (error) {
    encryptedAadhaar = encryptAadhaar(aadhaar);
    console.log('🔐 Encrypted plain text Aadhaar');
  }

  makeAadhaarSearchRequest(search, encryptedAadhaar, (err, response, body) => {
    if (err) {
      console.error('❌ Aadhaar search failed:', err.message);
      return res.status(500).json({
        success: false,
        error: err.message
      });
    }

    try {
      const parsedResults = parseSearchResults(body);

      if (parsedResults.error) {
        return res.status(404).json({
          success: false,
          error: parsedResults.error
        });
      }

      res.json({
        success: true,
        count: parsedResults.length,
        results: parsedResults
      });

      console.log(`✅ Aadhaar search completed. Found ${parsedResults.length} ration card(s)`);
    } catch (parseError) {
      console.error('❌ HTML parsing error in search results:', parseError);
      return res.status(500).json({
        success: false,
        error: 'Failed to parse search results'
      });
    }
  });
});

app.get('/crypto', (req, res) => {
  const action = req.query.action;
  const text = req.query.text;

  if (!action || !text) {
    return res.status(400).json({
      success: false,
      error: 'Missing parameters. Required: action and text'
    });
  }

  try {
    let result;
    if (action.toLowerCase() === 'encrypt') {
      result = encryptAadhaar(text);
      res.json({
        success: true,
        action: 'encrypt',
        original: text,
        encrypted: result
      });
    } else if (action.toLowerCase() === 'decrypt') {
      result = decryptAadhaar(text);
      res.json({
        success: true,
        action: 'decrypt',
        encrypted: text,
        decrypted: result
      });
    } else {
      return res.status(400).json({
        success: false,
        error: 'Invalid action. Use "encrypt" or "decrypt"'
      });
    }
  } catch (error) {
    console.error('❌ Crypto operation failed:', error.message);
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'IMPDS Aadhaar Search API',
    session_active: !!currentJSESSIONID,
    session_age: sessionLastUpdated ? Math.round((new Date() - sessionLastUpdated) / (1000 * 60)) + ' minutes' : 'N/A',
    endpoints: {
      aadhaar_search: '/search-aadhaar?search=A&aadhaar=AADHAAR_NUMBER',
      crypto: '/crypto?action=encrypt|decrypt&text=TEXT',
      health: '/health'
    },
    status: 'Server is running'
  });
});

async function initializeServer() {
  let retries = 0;
  const maxRetries = 10;

  while (retries < maxRetries) {
    try {
      console.log(`🚀 Initializing server (attempt ${retries + 1}/${maxRetries})...`);
      await getFreshJSESSIONID();
      console.log('✅ Server initialized with valid session');
      console.log('🔐 Encryption key loaded');

      app.listen(PORT, () => {
        console.log(`🎉 Server running at http://localhost:${PORT}`);
        console.log(`🔑 Current JSESSIONID: ${currentJSESSIONID}`);
        console.log('\nAvailable endpoints:');
        console.log('• GET /search-aadhaar?search=A&aadhaar=NUMBER - Search by Aadhaar');
        console.log('• GET /crypto?action=encrypt|decrypt&text=TEXT - Encrypt/decrypt text');
        console.log('• GET /health - Server health check');
      });
      return;
    } catch (error) {
      retries++;
      console.error(`❌ Initialization attempt ${retries} failed:`, error.message);

      if (retries < maxRetries) {
        console.log(`🔄 Retrying in 5 seconds...`);
        await new Promise(resolve => setTimeout(resolve, 5000));
      } else {
        console.error('💥 Session init failed, starting server anyway');
        app.listen(PORT, () => console.log(`Server running on port ${PORT} (no session yet)`));
        return;
      }
    }
  }
}

initializeServer();
