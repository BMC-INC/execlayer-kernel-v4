const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function isProduction() {
  return process.env.NODE_ENV !== 'development';
}

let _adapter = null;

async function getAdapter() {
  if (_adapter) return _adapter;

  if (isProduction()) {
    const { PostgresJournal } = await import('./journal_postgres.js');
    _adapter = PostgresJournal;
  } else {
    // Development only — filesystem journal
    const { Journal } = await import('./journal.js');
    _adapter = Journal;
  }
  return _adapter;
}

export const JournalAdapter = {

  getHead: async () => {
    const adapter = await getAdapter();
    return adapter.getHead();
  },

  writeReceipt: async (receipt) => {
    const adapter = await getAdapter();
    return adapter.writeReceipt(receipt);
  },

  getReceipt: async (hash) => {
    const adapter = await getAdapter();
    if (adapter.getReceipt) {
      return adapter.getReceipt(hash);
    }
    return null;
  },

  readAllReceipts: async () => {
    const adapter = await getAdapter();
    if (adapter.readAllReceipts) {
      return adapter.readAllReceipts();
    }
    // Fallback for filesystem
    if (adapter.readLedger) {
      return adapter.readLedger();
    }
    return [];
  },

  getGenesisHash: () => GENESIS_HASH,

  getBackendType: () => isProduction() ? 'postgres' : 'filesystem'
};
