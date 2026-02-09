export function canonicalStringify(obj) {
  if (obj === null || obj === undefined) {
    return 'null';
  }
  if (typeof obj === 'boolean' || typeof obj === 'number') {
    return JSON.stringify(obj);
  }
  if (typeof obj === 'string') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalStringify(item)).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    const pairs = [];
    for (const key of keys) {
      if (obj[key] !== undefined) {
        pairs.push(JSON.stringify(key) + ':' + canonicalStringify(obj[key]));
      }
    }
    return '{' + pairs.join(',') + '}';
  }
  return 'null';
}
