const DB_NAME = "cerberus";
const DB_VERSION = 1;
const STORE = "results";
const LS_KEY = "cerberus_results_fallback";

let dbPromise = null;

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    if (!("indexedDB" in window)) {
      reject(new Error("no-indexeddb"));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, { keyPath: "id" });
        store.createIndex("timestamp", "timestamp");
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

function lsRead() {
  try {
    return JSON.parse(localStorage.getItem(LS_KEY) || "[]");
  } catch {
    return [];
  }
}

function lsWrite(list) {
  localStorage.setItem(LS_KEY, JSON.stringify(list));
}

export async function saveResult(entry) {
  const record = {
    id: entry.id || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type: entry.type,
    input: entry.input,
    verdict: entry.verdict,
    riskScore: entry.riskScore,
    flags: entry.flags || [],
    timestamp: entry.timestamp || Date.now(),
    raw: entry.raw || null,
  };
  try {
    const db = await openDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(record);
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    const list = lsRead();
    list.unshift(record);
    lsWrite(list);
  }
  return record;
}

export async function listResults() {
  try {
    const db = await openDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).getAll();
      req.onsuccess = () => resolve(req.result.sort((a, b) => b.timestamp - a.timestamp));
      req.onerror = () => reject(req.error);
    });
  } catch {
    return lsRead();
  }
}

export async function deleteResult(id) {
  try {
    const db = await openDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(id);
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    lsWrite(lsRead().filter((r) => r.id !== id));
  }
}

export async function clearAll() {
  try {
    const db = await openDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).clear();
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    lsWrite([]);
  }
}
