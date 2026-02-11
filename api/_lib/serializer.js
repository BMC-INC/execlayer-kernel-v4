import { canonicalStringify } from './canonical.js';

export const UnifiedSerializer = {
  serialize: (data) => {
    // Uses canonical stringify to ensure deterministic output
    return canonicalStringify(data);
  },

  serializeError: (code, message, context = {}) => {
    return {
      status: 'REFUSE',
      error_code: code,
      message: message,
      context: context,
      timestamp: Date.now()
    };
  }
};
