'use strict';

const crypto = require('crypto');

/**
 * Placeholder "address generator".
 * This does NOT generate real BTC keys. It creates a stable, address-like identifier.
 *
 * To support real BTC safely:
 * - Use regtest/testnet + an external wallet daemon you control (e.g., Bitcoin Core)
 * - Or use watch-only addresses derived outside the app
 * - Or use a compliant payment processor API
 */
function generateUserWalletAddress() {
  const bytes = crypto.randomBytes(20).toString('hex');
  // Looks "btc-ish" but is NOT a real address
  return `demo_btc_${bytes}`;
}

module.exports = { generateUserWalletAddress };