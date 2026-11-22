/* builds a client-side search index (generated test fixture) */
self.onmessage = async () => {
  const terms = new Map();
  for (let i = 0; i < 6; i++) {
    try {
      const r = await fetch('../data/products-' + i + '.json');
      if (!r.ok) continue;
      for (const p of await r.json()) for (const w of (p.name + ' ' + p.blurb).toLowerCase().split(/\W+/)) terms.set(w, (terms.get(w) || 0) + 1);
    } catch (e) { /* offline is fine */ }
  }
  self.postMessage({ terms: terms.size });
};
