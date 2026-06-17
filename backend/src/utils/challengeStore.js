const store = new Map();
const TTL_MS = 5 * 60 * 1000;

module.exports = {
  set(userId, challenge) {
    store.set(String(userId), { challenge, expires: Date.now() + TTL_MS });
  },
  get(userId) {
    const entry = store.get(String(userId));
    if (!entry || Date.now() > entry.expires) {
      store.delete(String(userId));
      return null;
    }
    return entry.challenge;
  },
  delete(userId) {
    store.delete(String(userId));
  }
};
