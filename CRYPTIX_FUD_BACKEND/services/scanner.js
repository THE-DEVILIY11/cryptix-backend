const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const net = require('net');
const { query } = require('../config/db');
require('dotenv').config();

class Scanner {
  constructor() {
    this.vtApiKey = process.env.VT_API_KEY || '';
    this.vtApiUrl = 'https://www.virustotal.com/api/v3';
    this.rateLimitDelay = 15000; // 15 seconds between VT requests (free tier)
    this.lastRequestTime = 0;
  }

  /**
   * Scan an APK file against real VirusTotal API
   * Falls back to ClamAV local scan if VT key not configured
   */
  async scan(apkPath, fileId, userId) {
    if (!fs.existsSync(apkPath)) {
      throw new Error('File not found: ' + apkPath);
    }

    console.log('[Scanner] Starting real scan of:', apkPath);

    // Try VirusTotal first if API key is configured
    if (this.vtApiKey && this.vtApiKey !== 'your_virustotal_api_key_here') {
      try {
        return await this._scanWithVirusTotal(apkPath, fileId, userId);
      } catch (err) {
        console.error('[Scanner] VirusTotal scan failed, falling back:', err.message);
        return await this._scanWithClamAV(apkPath, fileId, userId);
      }
    }

    // Fallback to ClamAV local scan
    return await this._scanWithClamAV(apkPath, fileId, userId);
  }

  /**
   * Scan using real VirusTotal API
   */
  async _scanWithVirusTotal(filePath, fileId, userId) {
    // Enforce rate limiting
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    if (timeSinceLastRequest < this.rateLimitDelay) {
      await this._sleep(this.rateLimitDelay - timeSinceLastRequest);
    }

    const fileName = path.basename(filePath);
    const fileBuffer = fs.readFileSync(filePath);
    const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    console.log('[Scanner] Checking VirusTotal for hash:', fileHash);

    // Step 1: Check if file has already been analyzed by hash
    let analysisResult;
    try {
      analysisResult = await this._vtGetRequest('/files/' + fileHash);

      if (analysisResult && analysisResult.data) {
        this.lastRequestTime = Date.now();
        console.log('[Scanner] Found existing analysis on VirusTotal');
        return this._parseVTResponse(analysisResult, fileHash);
      }
    } catch (err) {
      // Hash not found, need to upload
      console.log('[Scanner] Hash not found on VT, uploading file...');
    }

    // Step 2: Upload file to VirusTotal
    this.lastRequestTime = Date.now();
    const uploadResult = await this._vtUploadFile(filePath, fileName);

    if (!uploadResult || !uploadResult.data || !uploadResult.data.id) {
      throw new Error('VirusTotal upload failed — no analysis ID returned');
    }

    const analysisId = uploadResult.data.id;
    console.log('[Scanner] File uploaded, analysis ID:', analysisId);

    // Step 3: Wait for analysis to complete
    await this._sleep(30000); // Wait 30 seconds for analysis

    // Step 4: Get analysis results
    this.lastRequestTime = Date.now();
    let retries = 0;
    const maxRetries = 6;

    while (retries < maxRetries) {
      try {
        analysisResult = await this._vtGetRequest('/analyses/' + analysisId);

        if (analysisResult && analysisResult.data &&
          analysisResult.data.attributes &&
          analysisResult.data.attributes.status === 'completed') {
          return this._parseVTResponse(analysisResult, fileHash);
        }

        retries++;
        console.log('[Scanner] Analysis not complete, waiting... (' + retries + '/' + maxRetries + ')');
        await this._sleep(15000);
        this.lastRequestTime = Date.now();
      } catch (err) {
        console.error('[Scanner] Error fetching analysis:', err.message);
        retries++;
        await this._sleep(10000);
      }
    }

    throw new Error('VirusTotal analysis did not complete in time');
  }

  /**
   * Make GET request to VirusTotal API
   */
  _vtGetRequest(endpoint) {
    return new Promise((resolve, reject) => {
      const url = this.vtApiUrl + endpoint;

      const options = {
        method: 'GET',
        headers: {
          'x-apikey': this.vtApiKey,
          'Accept': 'application/json'
        }
      };

      const req = https.request(url, options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (res.statusCode === 200 || res.statusCode === 201) {
              resolve(parsed);
            } else if (res.statusCode === 404) {
              resolve(null); // Hash not found
            } else {
              reject(new Error('VT API error ' + res.statusCode + ': ' + (parsed.error?.message || data)));
            }
          } catch (e) {
            reject(new Error('Failed to parse VT response: ' + e.message));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(30000, () => {
        req.destroy();
        reject(new Error('VT request timeout'));
      });
      req.end();
    });
  }

  /**
   * Upload file to VirusTotal
   */
  _vtUploadFile(filePath, fileName) {
    return new Promise((resolve, reject) => {
      const boundary = '----' + crypto.randomBytes(16).toString('hex');

      // Read file and build multipart form data
      const fileContent = fs.readFileSync(filePath);
      const header = Buffer.from(
        '--' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="file"; filename="' + fileName + '"\r\n' +
        'Content-Type: application/octet-stream\r\n\r\n'
      );
      const footer = Buffer.from('\r\n--' + boundary + '--\r\n');

      const bodyBuffer = Buffer.concat([header, fileContent, footer]);

      const options = {
        hostname: 'www.virustotal.com',
        path: '/api/v3/files',
        method: 'POST',
        headers: {
          'x-apikey': this.vtApiKey,
          'Content-Type': 'multipart/form-data; boundary=' + boundary,
          'Content-Length': bodyBuffer.length
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (res.statusCode === 200) {
              resolve(parsed);
            } else {
              reject(new Error('VT upload error ' + res.statusCode + ': ' + (parsed.error?.message || data)));
            }
          } catch (e) {
            reject(new Error('Failed to parse VT upload response: ' + e.message));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(120000, () => {
        req.destroy();
        reject(new Error('VT upload timeout'));
      });
      req.write(bodyBuffer);
      req.end();
    });
  }

  /**
   * Parse VirusTotal API response into our standard format
   */
  _parseVTResponse(response, fileHash) {
    const attributes = response.data?.attributes || {};
    const stats = attributes.stats || {};
    const results = attributes.results || {};

    const totalEngines = (stats.harmless || 0) + (stats.malicious || 0) +
      (stats.suspicious || 0) + (stats.undetected || 0) +
      (stats.timeout || 0);

    const detections = (stats.malicious || 0) + (stats.suspicious || 0);
    const fudRate = totalEngines > 0 ? Math.round(((totalEngines - detections) / totalEngines) * 100) : 100;

    // Build detailed engine results
    const engineResults = [];
    for (const [engine, result] of Object.entries(results)) {
      engineResults.push({
        engine,
        detected: result.category === 'malicious' || result.category === 'suspicious',
        category: result.category || 'undetected',
        signature: result.result || null,
        version: result.engine_version || 'unknown'
      });
    }

    return {
      totalEngines,
      detections,
      fudRate,
      scanId: response.data?.id || fileHash,
      timestamp: new Date().toISOString(),
      fileHash,
      source: 'virustotal',
      results: engineResults,
      vtUrl: 'https://www.virustotal.com/gui/file/' + fileHash
    };
  }

  /**
   * Scan using real ClamAV
   */
  async _scanWithClamAV(filePath, fileId, userId) {
    console.log('[Scanner] Scanning with ClamAV:', filePath);

    // Method 1: Try clamd (daemon mode) via TCP
    try {
      return await this._scanWithClamd(filePath);
    } catch (err) {
      console.log('[Scanner] Clamd scan failed:', err.message);
    }

    // Method 2: Try clamscan (command-line)
    try {
      return await this._scanWithClamscan(filePath);
    } catch (err) {
      console.log('[Scanner] Clamscan also failed:', err.message);
    }

    // Method 3: Try local socket
    try {
      return await this._scanWithClamavSocket(filePath);
    } catch (err) {
      console.log('[Scanner] All ClamAV methods failed:', err.message);
    }

    // If nothing works, return error
    throw new Error('No antivirus scanner available. Install ClamAV or configure VirusTotal API key.');
  }

  /**
   * Scan with clamd (TCP daemon on port 3310)
   */
  _scanWithClamd(filePath) {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let timeout = setTimeout(() => {
        socket.destroy();
        reject(new Error('Clamd connection timeout'));
      }, 10000);

      socket.connect(3310, '127.0.0.1', () => {
        clearTimeout(timeout);
        // Send INSTREAM command
        const streamCmd = Buffer.from('zINSTREAM\0');
        socket.write(streamCmd);

        // Read file and send in chunks
        const fileBuffer = fs.readFileSync(filePath);
        const chunkSize = 1024 * 64;

        for (let i = 0; i < fileBuffer.length; i += chunkSize) {
          const chunk = fileBuffer.slice(i, i + chunkSize);
          const sizeBuf = Buffer.alloc(4);
          sizeBuf.writeUInt32BE(chunk.length, 0);
          socket.write(Buffer.concat([sizeBuf, chunk]));
        }

        // Signal end of file
        const endBuf = Buffer.alloc(4);
        endBuf.writeUInt32BE(0, 0);
        socket.write(endBuf);
      });

      let response = '';
      socket.on('data', (data) => {
        response += data.toString();
      });

      socket.on('close', () => {
        clearTimeout(timeout);
        const isClean = response.includes('OK') && !response.includes('FOUND');

        resolve({
          totalEngines: 1,
          detections: isClean ? 0 : 1,
          fudRate: isClean ? 100 : 0,
          scanId: crypto.randomBytes(8).toString('hex'),
          timestamp: new Date().toISOString(),
          fileHash: this._hashFile(filePath),
          source: 'clamav',
          results: [{
            engine: 'ClamAV',
            detected: !isClean,
            category: isClean ? 'clean' : 'malicious',
            signature: isClean ? null : response.trim(),
            version: '1.0'
          }],
          raw: response.trim()
        });
      });

      socket.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
  }

  /**
   * Scan with command-line clamscan
   */
  _scanWithClamscan(filePath) {
    return new Promise((resolve, reject) => {
      const {
        exec
      } = require('child_process');

      exec('clamscan --stdout --no-summary "' + filePath + '"', {
        timeout: 60000,
        maxBuffer: 1024 * 1024
      }, (error, stdout, stderr) => {
        const result = stdout.trim();
        const isClean = !result || result.includes('OK');
        const detected = result.includes('FOUND');

        resolve({
          totalEngines: 1,
          detections: detected ? 1 : 0,
          fudRate: detected ? 0 : 100,
          scanId: crypto.randomBytes(8).toString('hex'),
          timestamp: new Date().toISOString(),
          fileHash: this._hashFile(filePath),
          source: 'clamscan',
          results: [{
            engine: 'ClamAV',
            detected: detected,
            category: detected ? 'malicious' : 'clean',
            signature: detected ? result : null,
            version: '1.0'
          }],
          raw: result
        });
      });
    });
  }

  /**
   * Scan via ClamAV Unix socket
   */
  _scanWithClamavSocket(filePath) {
    return new Promise((resolve, reject) => {
      const net = require('net');
      const socketPaths = [
        '/var/run/clamav/clamd.ctl',
        '/tmp/clamd.socket',
        '/var/run/clamd.scan/clamd.sock'
      ];

      let attempted = 0;

      function trySocket(sockPath) {
        const client = new net.Socket();
        let responded = false;
        let timeout = setTimeout(() => {
          if (!responded) {
            client.destroy();
            attempted++;
            if (attempted >= socketPaths.length) {
              reject(new Error('All ClamAV sockets failed'));
            } else {
              trySocket(socketPaths[attempted]);
            }
          }
        }, 5000);

        client.connect(sockPath, () => {
          clearTimeout(timeout);
          const cmd = 'zINSTREAM\0';
          client.write(cmd);

          const fileBuffer = fs.readFileSync(filePath);
          const chunkSize = 1024 * 64;

          for (let i = 0; i < fileBuffer.length; i += chunkSize) {
            const chunk = fileBuffer.slice(i, i + chunkSize);
            const sizeBuf = Buffer.alloc(4);
            sizeBuf.writeUInt32BE(chunk.length, 0);
            client.write(Buffer.concat([sizeBuf, chunk]));
          }

          const endBuf = Buffer.alloc(4);
          endBuf.writeUInt32BE(0, 0);
          client.write(endBuf);
        });

        let data = '';
        client.on('data', (d) => {
          data += d.toString();
        });

        client.on('close', () => {
          if (!responded) {
            responded = true;
            clearTimeout(timeout);
            const isClean = data.includes('OK') && !data.includes('FOUND');
            const detected = data.includes('FOUND');

            resolve({
              totalEngines: 1,
              detections: detected ? 1 : 0,
              fudRate: detected ? 0 : 100,
              scanId: crypto.randomBytes(8).toString('hex'),
              timestamp: new Date().toISOString(),
              fileHash: this._hashFile(filePath),
              source: 'clamav',
              results: [{
                engine: 'ClamAV',
                detected: detected,
                category: detected ? 'malicious' : 'clean',
                signature: detected ? data.trim() : null,
                version: '1.0'
              }],
              raw: data.trim()
            });
          }
        });

        client.on('error', () => {
          clearTimeout(timeout);
          client.destroy();
          attempted++;
          if (attempted >= socketPaths.length) {
            reject(new Error('All ClamAV sockets failed'));
          } else {
            trySocket(socketPaths[attempted]);
          }
        });
      }

      trySocket(socketPaths[0]);
    });
  }

  /**
   * Quick scan status (just returns detections count)
   */
  async quickScan(filePath, fileId, userId) {
    const result = await this.scan(filePath, fileId, userId);
    return {
      totalEngines: result.totalEngines,
      detections: result.detections,
      fudRate: result.fudRate,
      scanId: result.scanId,
      source: result.source
    };
  }

  /**
   * Generate a scan report
   */
  generateReport(scanResult) {
    const detected = scanResult.results.filter(r => r.detected);
    const clean = scanResult.results.filter(r => !r.detected);

    return {
      summary: {
        total: scanResult.totalEngines,
        detected: scanResult.detections,
        clean: scanResult.totalEngines - scanResult.detections,
        fudRate: scanResult.fudRate,
        verdict: scanResult.detections === 0 ? 'FUD' : 'DETECTED',
        source: scanResult.source
      },
      topDetections: detected.slice(0, 10).map(d => ({
        engine: d.engine,
        signature: d.signature,
        category: d.category
      })),
      cleanEngines: clean.slice(0, 10).map(d => d.engine),
      scanInfo: {
        id: scanResult.scanId,
        timestamp: scanResult.timestamp,
        fileHash: scanResult.fileHash,
        totalEngines: scanResult.totalEngines,
        vtUrl: scanResult.vtUrl || null
      }
    };
  }

  _hashFile(filePath) {
    const buffer = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buffer).digest('hex');
  }

  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = new Scanner();
