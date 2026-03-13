require('dotenv').config();
const admin = require('firebase-admin');

let db = null;
let storageMode = 'memory';
const memStore = { scans: {}, findings: {} };

function initFirebase() {
  if (admin.apps.length > 0) return;

  const privateKey = process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined;
  const hasAdminConfig = Boolean(
    process.env.FIREBASE_PROJECT_ID &&
    process.env.FIREBASE_CLIENT_EMAIL &&
    privateKey &&
    /BEGIN PRIVATE KEY/.test(privateKey)
  );

  const hasWebConfig = Boolean(
    process.env.FIREBASE_API_KEY &&
    process.env.FIREBASE_AUTH_DOMAIN &&
    process.env.FIREBASE_PROJECT_ID &&
    process.env.FIREBASE_STORAGE_BUCKET &&
    process.env.FIREBASE_MESSAGING_SENDER_ID &&
    process.env.FIREBASE_APP_ID
  );

  if (!hasAdminConfig) {
    storageMode = 'memory';
    if (hasWebConfig) {
      console.warn('Firebase web config detected. Server persistence still needs Admin SDK credentials. Running in memory mode.');
    } else {
      console.warn('Firebase Admin credentials not configured. Running in memory mode.');
    }
    return;
  }

  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey,
      }),
    });
    db = admin.firestore();
    storageMode = 'firebase-admin';
    console.log('Firebase Admin initialized');
  } catch (err) {
    storageMode = 'memory';
    console.error('Firebase init error:', err.message);
  }
}

initFirebase();

module.exports = {
  async createScan(scanId, data) {
    if (db) await db.collection('scans').doc(scanId).set(data);
    else memStore.scans[scanId] = { ...data, findings: [] };
  },
  async updateScan(scanId, data) {
    if (db) await db.collection('scans').doc(scanId).update(data);
    else memStore.scans[scanId] = { ...(memStore.scans[scanId] || {}), ...data };
  },
  async addFinding(scanId, finding) {
    if (db) {
      await db.collection('scans').doc(scanId)
        .collection('findings').add({ ...finding, timestamp: admin.firestore.FieldValue.serverTimestamp() });
    } else {
      if (!memStore.findings[scanId]) memStore.findings[scanId] = [];
      memStore.findings[scanId].push({ ...finding, timestamp: new Date().toISOString() });
    }
  },
  async getScan(scanId) {
    if (db) {
      const doc = await db.collection('scans').doc(scanId).get();
      return doc.exists ? { id: doc.id, ...doc.data() } : null;
    }
    return memStore.scans[scanId] || null;
  },
  async getFindings(scanId) {
    if (db) {
      const snap = await db.collection('scans').doc(scanId)
        .collection('findings').orderBy('timestamp', 'asc').get();
      return snap.docs.map(d => ({ id: d.id, ...d.data() }));
    }
    return memStore.findings[scanId] || [];
  },
  async getAllScans() {
    if (db) {
      const snap = await db.collection('scans').orderBy('createdAt', 'desc').limit(50).get();
      return snap.docs.map(d => ({ id: d.id, ...d.data() }));
    }
    return Object.entries(memStore.scans).map(([id, data]) => ({ id, ...data })).reverse();
  },
  getStorageMode() {
    return storageMode;
  },
};
