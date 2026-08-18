const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  execSync
} = require('child_process');

class Signer {
  constructor() {
    this.certsDir = path.join(__dirname, '..', 'certs');
    this.binDir = path.join(__dirname, '..', 'bin');

    // Ensure certs directory exists
    if (!fs.existsSync(this.certsDir)) {
      fs.mkdirSync(this.certsDir, {
        recursive: true
      });
    }
  }

  /**
   * Sign an APK with a freshly generated certificate
   * Each signature is unique to evade signature-based detection
   * 
   * @param {string} unsignedApk - Path to the unsigned APK
   * @param {string} outputPath - Where to write the signed APK
   * @param {string} scheme - 'v1' (jarsigner) or 'v2' (apksigner)
   * @returns {object} signing result with path and certificate info
   */
  sign(unsignedApk, outputPath, scheme = 'v2') {
    if (!fs.existsSync(unsignedApk)) {
      throw new Error('Unsigned APK not found: ' + unsignedApk);
    }

    console.log('[Signer] Signing:', unsignedApk);

    // Generate random identity for this signing session
    const identity = this._generateIdentity();
    const keystorePath = path.join(this.certsDir, 'keystore_' + identity.alias + '.jks');
    const keystorePass = crypto.randomBytes(16).toString('hex');
    const keyPass = crypto.randomBytes(16).toString('hex');

    try {
      // Step 1: Generate keystore with real key pair
      console.log('[Signer] Generating keystore with RSA 2048 key...');
      this._exec(
        `keytool -genkey -v -keystore "${keystorePath}" ` +
        `-alias "${identity.alias}" ` +
        `-keyalg RSA -keysize 2048 -validity 7300 ` +
        `-storepass "${keystorePass}" -keypass "${keyPass}" ` +
        `-dname "CN=${identity.cn}, OU=${identity.ou}, O=${identity.o}, ` +
        `L=${identity.l}, ST=${identity.st}, C=${identity.c}"`,
        30000
      );

      // Step 2: Sign the APK
      if (scheme === 'v2') {
        this._signV2(keystorePath, keystorePass, identity.alias, unsignedApk, outputPath);
      } else {
        this._signV1(keystorePath, keystorePass, keyPass, identity.alias, unsignedApk, outputPath);
      }

      if (!fs.existsSync(outputPath)) {
        // If output path is different, copy
        fs.copyFileSync(unsignedApk, outputPath);
      }

      // Step 3: Verify signature
      const verification = this.verify(outputPath || unsignedApk);

      // Cleanup keystore
      try {
        fs.unlinkSync(keystorePath);
      } catch {}

      console.log('[Signer] Signing complete:', path.basename(outputPath || unsignedApk));

      return {
        success: true,
        signedPath: outputPath || unsignedApk,
        scheme,
        identity: identity.alias,
        certificate: {
          cn: identity.cn,
          ou: identity.ou,
          o: identity.o,
          validUntil: new Date(Date.now() + 7300 * 86400000).toISOString()
        },
        verification
      };

    } catch (err) {
      // Cleanup on failure
      try {
        fs.unlinkSync(keystorePath);
      } catch {}
      throw new Error('Signing failed: ' + err.message);
    }
  }

  /**
   * Sign with APK Signature Scheme v2 (using apksigner)
   * This is the modern Android signing method
   */
  _signV2(keystorePath, storePass, alias, unsignedApk, outputPath) {
    const apksignerPath = path.join(this.binDir, 'apksigner');

    // Try to use apksigner from Android SDK
    const sdkPaths = [
      '/opt/android-sdk/build-tools/34.0.0/apksigner',
      '/opt/android-sdk/build-tools/33.0.0/apksigner',
      '/opt/android-sdk/build-tools/32.0.0/apksigner',
      '/usr/local/lib/android/sdk/build-tools/34.0.0/apksigner',
      '/usr/local/lib/android/sdk/build-tools/33.0.0/apksigner',
      '/usr/local/lib/android/sdk/build-tools/32.0.0/apksigner',
    ];

    let apksignerExe = null;
    if (fs.existsSync(apksignerPath)) {
      apksignerExe = apksignerPath;
    } else {
      for (const p of sdkPaths) {
        if (fs.existsSync(p)) {
          apksignerExe = p;
          break;
        }
      }
    }

    if (apksignerExe) {
      // Use apksigner for v2 scheme signing
      this._exec(
        `"${apksignerExe}" sign ` +
        `--ks "${keystorePath}" ` +
        `--ks-pass "pass:${storePass}" ` +
        `--ks-key-alias "${alias}" ` +
        `--out "${outputPath || unsignedApk}" ` +
        `"${unsignedApk}"`,
        60000
      );
    } else {
      // Fallback to v1 signing with jarsigner
      console.log('[Signer] apksigner not found, falling back to jarsigner (v1 scheme)');
      this._exec(
        `jarsigner -sigalg SHA256withRSA -digestalg SHA-256 ` +
        `-keystore "${keystorePath}" ` +
        `-storepass "${storePass}" ` +
        `-keypass "${storePass}" ` +
        `"${unsignedApk}" "${alias}"`,
        60000
      );
    }
  }

  /**
   * Sign with v1 scheme using jarsigner
   */
  _signV1(keystorePath, storePass, keyPass, alias, unsignedApk, outputPath) {
    this._exec(
      `jarsigner -sigalg SHA256withRSA -digestalg SHA-256 ` +
      `-keystore "${keystorePath}" ` +
      `-storepass "${storePass}" ` +
      `-keypass "${keyPass}" ` +
      `"${unsignedApk}" "${alias}"`,
      60000
    );

    // Verify signing
    this._exec(
      `jarsigner -verify -keystore "${keystorePath}" ` +
      `-storepass "${storePass}" ` +
      `"${unsignedApk}" "${alias}"`,
      30000
    );
  }

  /**
   * Verify an APK's signature
   */
  verify(apkPath) {
    if (!fs.existsSync(apkPath)) {
      return {
        verified: false,
        error: 'File not found'
      };
    }

    try {
      const output = this._exec(`jarsigner -verify -certs "${apkPath}"`, 30000);
      const verified = output.includes('jar verified');

      // Extract certificate info
      const lines = output.split('\n').filter(l => l.includes('CN=') || l.includes('SHA'));

      return {
        verified,
        details: lines.slice(0, 3),
        raw: output.substring(0, 500)
      };
    } catch (err) {
      return {
        verified: false,
        error: err.message
      };
    }
  }

  /**
   * Generate a unique certificate identity
   */
  _generateIdentity() {
    const organizations = [
      'SecureSoft Inc.', 'AppDev Labs', 'MobileTech Corp',
      'ByteForge Ltd', 'CodeCraft Studios', 'Digital Vault',
      'CipherWorks', 'ShieldTech', 'Fortress Mobile',
      'NexGen Apps', 'Quantum Dev', 'Pinnacle Software'
    ];
    const countries = ['US', 'GB', 'DE', 'CA', 'AU', 'NL', 'JP', 'FR', 'CH', 'SE'];

    return {
      cn: 'CRYPTIX_' + crypto.randomBytes(6).toString('hex'),
      ou: 'Engineering_' + crypto.randomBytes(4).toString('hex'),
      o: organizations[Math.floor(Math.random() * organizations.length)],
      l: 'Development',
      st: 'Technical',
      c: countries[Math.floor(Math.random() * countries.length)],
      alias: crypto.randomBytes(12).toString('hex')
    };
  }

  /**
   * Generate a self-signed CA certificate for internal signing
   */
  generateCACertificate() {
    const caKeystore = path.join(this.certsDir, 'cryptix_ca.jks');
    const caPass = crypto.randomBytes(16).toString('hex');

    if (!fs.existsSync(caKeystore)) {
      this._exec(
        `keytool -genkey -v -keystore "${caKeystore}" ` +
        `-alias cryptix_ca -keyalg RSA -keysize 4096 -validity 7300 ` +
        `-storepass "${caPass}" -keypass "${caPass}" ` +
        `-dname "CN=CRYPTIX CA, OU=Certificate Authority, O=CRYPTIX, C=XX" ` +
        `-ext bc:c=ca:true,pathlen:1`,
        30000
      );
    }

    return {
      keystore: caKeystore,
      password: caPass
    };
  }

  _exec(command, timeout = 60000) {
    try {
      return execSync(command, {
        timeout,
        maxBuffer: 10 * 1024 * 1024,
        encoding: 'utf8',
        stdio: 'pipe'
      });
    } catch (err) {
      throw new Error(err.stderr ? err.stderr.toString() : err.message);
    }
  }
}

module.exports = new Signer();
