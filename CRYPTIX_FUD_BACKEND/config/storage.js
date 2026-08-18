const fs = require('fs');
const path = require('path');
const {
  v4: uuidv4
} = require('uuid');
require('dotenv').config();

const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE) || 52428800;
const FILE_EXPIRY_DAYS = parseInt(process.env.FILE_EXPIRY_DAYS) || 30;

// Ensure upload directories exist
const dirs = [
  path.join(UPLOAD_DIR, 'original'),
  path.join(UPLOAD_DIR, 'crypted'),
  path.join(UPLOAD_DIR, 'temp'),
];

dirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, {
      recursive: true
    });
    console.log(`[STORAGE] Created directory: ${dir}`);
  }
});

function getOriginalPath(userId, fileId) {
  const userDir = path.join(UPLOAD_DIR, 'original', userId);
  if (!fs.existsSync(userDir)) {
    fs.mkdirSync(userDir, {
      recursive: true
    });
  }
  return path.join(userDir, `${fileId}.apk`);
}

function getCryptedPath(userId, fileId) {
  const userDir = path.join(UPLOAD_DIR, 'crypted', userId);
  if (!fs.existsSync(userDir)) {
    fs.mkdirSync(userDir, {
      recursive: true
    });
  }
  return path.join(userDir, `${fileId}_crypted.apk`);
}

function getTempPath() {
  return path.join(UPLOAD_DIR, 'temp', `${uuidv4()}.apk`);
}

function getFileSize(filePath) {
  try {
    const stats = fs.statSync(filePath);
    return stats.size;
  } catch {
    return 0;
  }
}

function deleteFile(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      return true;
    }
  } catch (err) {
    console.error('[STORAGE] Delete error:', err.message);
  }
  return false;
}

function calculateStorageUsed(userId) {
  const userDir = path.join(UPLOAD_DIR, 'crypted', userId);
  if (!fs.existsSync(userDir)) return 0;
  let total = 0;
  const files = fs.readdirSync(userDir);
  files.forEach(file => {
    const filePath = path.join(userDir, file);
    total += getFileSize(filePath);
  });
  return total;
}

module.exports = {
  UPLOAD_DIR,
  MAX_FILE_SIZE,
  FILE_EXPIRY_DAYS,
  getOriginalPath,
  getCryptedPath,
  getTempPath,
  getFileSize,
  deleteFile,
  calculateStorageUsed,
};
