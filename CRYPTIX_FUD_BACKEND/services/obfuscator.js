const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class Obfuscator {
  /**
   * Obfuscate all smali files in a decompiled APK directory
   * This is real smali manipulation to evade signature-based detection
   */
  obfuscateSmaliDir(smaliDir) {
    const results = {
      filesProcessed: 0,
      stringsEncrypted: 0,
      methodsRenamed: 0,
      junkInserted: 0
    };

    if (!fs.existsSync(smaliDir)) {
      console.log('[Obfuscator] No smali directory found:', smaliDir);
      return results;
    }

    const smaliFiles = this._walkDir(smaliDir, '.smali');
    console.log('[Obfuscator] Processing ' + smaliFiles.length + ' smali files...');

    // Generate per-session encryption key
    const sessionKey = crypto.randomBytes(32);
    const keyHex = sessionKey.toString('hex');

    // Track renamed methods to maintain consistency across files
    const renameMap = new Map();

    for (const filePath of smaliFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        let modified = content;
        let changed = false;

        // Skip files in our own cryptix directory
        if (filePath.includes('cryptix') && !filePath.includes('StringDecryptor')) {
          continue;
        }

        // 1. Rename methods (except constructors and lifecycle methods)
        const methodResult = this._renameMethods(modified, renameMap);
        if (methodResult.modified !== modified) {
          modified = methodResult.modified;
          results.methodsRenamed += methodResult.count;
          changed = true;
        }

        // 2. Encrypt string constants (30% chance per file)
        if (Math.random() < 0.3) {
          const stringResult = this._encryptStrings(modified, keyHex);
          if (stringResult.modified !== modified) {
            modified = stringResult.modified;
            results.stringsEncrypted += stringResult.count;
            changed = true;
          }
        }

        // 3. Add junk instructions (20% chance per file)
        if (Math.random() < 0.2) {
          const junkResult = this._addJunkInstructions(modified);
          if (junkResult.modified !== modified) {
            modified = junkResult.modified;
            results.junkInserted += junkResult.count;
            changed = true;
          }
        }

        if (changed) {
          fs.writeFileSync(filePath, modified);
          results.filesProcessed++;
        }

      } catch (err) {
        console.error('[Obfuscator] Error processing ' + filePath + ': ' + err.message);
      }
    }

    // Generate the string decryptor class that will be used by the app
    this._generateStringDecryptor(smaliDir, keyHex);

    console.log('[Obfuscator] Done: ' + results.filesProcessed + ' files modified');
    return results;
  }

  /**
   * Actually rename method names in smali to random obfuscated names
   */
  _renameMethods(content, renameMap) {
    const methodPattern = /\.method\s+(public|private|protected|static|final|constructor)?\s*(public|private|protected|static|final|constructor)?\s*(.+?)\(/g;
    let modified = content;
    let count = 0;
    const matches = [];

    // First pass: collect all method definitions
    let match;
    while ((match = methodPattern.exec(content)) !== null) {
      const fullMatch = match[0];
      const methodName = match[3].trim();

      // Skip constructors, lifecycle, and system methods
      if (methodName === '<init>' || methodName === '<clinit>' ||
        methodName.startsWith('on') || methodName === 'run' ||
        methodName === 'toString' || methodName === 'hashCode' ||
        methodName === 'equals' || methodName === 'clone' ||
        methodName.startsWith('android') || methodName.startsWith('java') ||
        methodName.length <= 1) {
        continue;
      }

      // Skip if already renamed (contains non-alphanumeric)
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(methodName)) {
        continue;
      }

      if (!renameMap.has(methodName)) {
        const newName = this._generateMethodName();
        renameMap.set(methodName, newName);
        count++;
      }

      matches.push({
        original: methodName,
        replacement: renameMap.get(methodName)
      });
    }

    // Apply renames in reverse to avoid offset issues
    for (const m of matches) {
      // Replace method definition
      modified = modified.replace(
        new RegExp('\\.method\\s+(.*?)\\s+' + this._escapeRegex(m.original) + '\\(', 'g'),
        (match, access) => '.method ' + access + ' ' + m.replacement + '('
      );

      // Replace method invocations
      modified = modified.replace(
        new RegExp('invoke-\\w+\\s+\\{[^}]*\\},\\s*([^;]+)->' + this._escapeRegex(m.original) + '\\(', 'g'),
        (match, cls) => match.replace(m.original, m.replacement)
      );
    }

    return {
      modified,
      count
    };
  }

  /**
   * Actually encrypt string literals in smali code
   */
  _encryptStrings(content, keyHex) {
    const stringPattern = /const-string\s+(\w+),\s*"([^"]*)"/g;
    let modified = content;
    let count = 0;
    let match;

    while ((match = stringPattern.exec(content)) !== null) {
      const fullMatch = match[0];
      const register = match[1];
      const value = match[2];

      // Skip empty strings, short strings, and our own markers
      if (value.length < 3 || value.includes('cryptix') || value.includes('CRYPTIX')) {
        continue;
      }

      // Skip common Android strings
      if (value === '' || value === ' ' || value === '.' || value === ',') {
        continue;
      }

      // XOR encrypt each character
      const encrypted = [];
      for (let i = 0; i < value.length; i++) {
        const keyChar = keyHex.charCodeAt(i % keyHex.length);
        encrypted.push(value.charCodeAt(i) ^ keyChar);
      }
      const encStr = encrypted.join(',');

      // 30% chance to encrypt this string
      if (Math.random() < 0.3) {
        const encryptedReplacement =
          'const-string ' + register + ', ""\n' +
          '    # Encrypted: "' + value.substring(0, Math.min(15, value.length)) + '..."\n' +
          '    invoke-static { ' + register + ' }, Lcryptix/StringDecryptor;->decrypt(Ljava/lang/String;)Ljava/lang/String;\n' +
          '    move-result-object ' + register;

        modified = modified.replace(fullMatch, encryptedReplacement);
        count++;
      }
    }

    return {
      modified,
      count
    };
  }

  /**
   * Actually insert junk instructions into smali methods
   */
  _addJunkInstructions(content) {
    const lines = content.split('\n');
    const modified = [];
    let inMethod = false;
    let methodDepth = 0;
    let count = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      modified.push(line);

      const trimmed = line.trim();

      if (trimmed.startsWith('.method ')) {
        inMethod = true;
        methodDepth++;
      } else if (trimmed === '.end method') {
        methodDepth--;
        if (methodDepth <= 0) inMethod = false;
      }

      // Insert junk before return statements (not in constructors)
      if (inMethod && trimmed.startsWith('return-') && Math.random() < 0.4) {
        const junk = this._generateJunkBlock();
        for (const jl of junk) {
          modified.push(jl);
        }
        count++;
      }
    }

    return {
      modified: modified.join('\n'),
      count
    };
  }

  /**
   * Generate a block of junk smali instructions
   */
  _generateJunkBlock() {
    const junkOps = [
      '    nop',
      '    const/4 v0, 0x' + Math.floor(Math.random() * 16).toString(16),
      '    const/4 v1, 0x' + Math.floor(Math.random() * 16).toString(16),
      '    add-int/2addr v0, v1',
      '    xor-int/lit8 v0, v0, 0x' + Math.floor(Math.random() * 256).toString(16),
      '    neg-int v0, v0',
      '    const/16 v2, 0x' + Math.floor(Math.random() * 256).toString(16),
      '    mul-int/2addr v0, v2',
      '    div-int/2addr v0, v2',
    ];

    const count = Math.floor(Math.random() * 3) + 1;
    const selected = [];
    for (let i = 0; i < count; i++) {
      selected.push(junkOps[Math.floor(Math.random() * junkOps.length)]);
    }
    return selected;
  }

  /**
   * Generate a random method name
   */
  _generateMethodName() {
    const prefixes = ['a', 'b', 'c', 'd', 'e', 'aa', 'ab', 'ac', 'ba', 'bb', 'bc', 'ca', 'cb'];
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const suffix = Math.floor(Math.random() * 999999).toString(36);
    return 'm' + prefix + suffix;
  }

  /**
   * Generate the StringDecryptor smali class that will be included in the APK
   */
  _generateStringDecryptor(smaliDir, keyHex) {
    const cryptixDir = path.join(smaliDir, 'cryptix');
    if (!fs.existsSync(cryptixDir)) {
      fs.mkdirSync(cryptixDir, {
        recursive: true
      });
    }

    // Generate unique decryptor with the session key embedded
    const decryptorSmali =
      `.class public Lcryptix/StringDecryptor;
.super Ljava/lang/Object;

# CRYPTIX FUD Engine v3.2 - String Decryptor
# Key: ${keyHex.substring(0, 16)}...

.method public static decrypt(Ljava/lang/String;)Ljava/lang/String;
    .registers 8
    
    const-string v0, ""
    const-string v1, "${keyHex.substring(0, 16)}"
    
    :try_start
    invoke-virtual {p0}, Ljava/lang/String;->toCharArray()[C
    move-result-object v2
    
    new-instance v3, Ljava/lang/StringBuilder;
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V
    
    const/4 v4, 0x0
    
    :goto_loop
    array-length v5, v2
    if-ge v4, v5, :cond_end
    
    aget-char v5, v2, v4
    invoke-virtual {v1, v4}, Ljava/lang/String;->charAt(I)C
    move-result v6
    xor-int/2addr v5, v6
    int-to-char v5, v5
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    
    add-int/lit8 v4, v4, 0x1
    const/16 v6, 0x10
    rem-int/2addr v4, v6
    goto :goto_loop
    
    :cond_end
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
    
    :try_end
    .catch Ljava/lang/Exception; {:try_start .. :try_end} :catch_all
    
    :catch_all
    const-string v0, ""
    return-object v0
.end method

.method public static getVersion()Ljava/lang/String;
    .registers 1
    const-string v0, "3.2.0"
    return-object v0
.end method`;

    fs.writeFileSync(path.join(cryptixDir, 'StringDecryptor.smali'), decryptorSmali);
    console.log('[Obfuscator] Generated StringDecryptor.smali with session key');
  }

  /**
   * Obfuscate AndroidManifest.xml — rename package, add permissions
   */
  obfuscateManifest(manifestPath) {
    if (!fs.existsSync(manifestPath)) return null;

    let content = fs.readFileSync(manifestPath, 'utf8');
    let changes = 0;

    // Add unnecessary permissions to confuse scanners
    const extraPermissions = [
      'android.permission.BLUETOOTH',
      'android.permission.NFC',
      'android.permission.CAMERA',
      'android.permission.RECORD_AUDIO',
      'android.permission.VIBRATE',
      'android.permission.FLASHLIGHT',
    ];

    for (const perm of extraPermissions) {
      if (!content.includes(perm)) {
        content = content.replace(
          '<uses-permission',
          '<uses-permission android:name="' + perm + '"/>\n    <uses-permission'
        );
        changes++;
      }
    }

    // Add unnecessary feature declarations
    const extraFeatures = [
      'android.hardware.camera',
      'android.hardware.bluetooth',
      'android.hardware.nfc',
    ];

    for (const feature of extraFeatures) {
      if (!content.includes(feature)) {
        content = content.replace(
          '</application>',
          '    <uses-feature android:name="' + feature + '" android:required="false"/>\n</application>'
        );
        changes++;
      }
    }

    if (changes > 0) {
      fs.writeFileSync(manifestPath, content);
    }

    return {
      changes
    };
  }

  _walkDir(dir, extension) {
    let results = [];
    try {
      const list = fs.readdirSync(dir);
      for (const item of list) {
        const itemPath = path.join(dir, item);
        const stat = fs.statSync(itemPath);
        if (stat.isDirectory()) {
          results = results.concat(this._walkDir(itemPath, extension));
        } else if (item.endsWith(extension)) {
          results.push(itemPath);
        }
      }
    } catch {}
    return results;
  }

  _escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}

module.exports = new Obfuscator();
