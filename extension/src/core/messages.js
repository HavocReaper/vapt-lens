/**
 * messages.js — shared message type constants and a tiny browser API shim
 * that works with Chrome (callback style) and Firefox (promise style).
 */

export const SCAN_PAGE = 'SCAN_PAGE';
export const SCAN_RESULT = 'SCAN_RESULT';
export const GET_STATE = 'GET_STATE';
export const STATE = 'STATE';
export const OPEN_PANEL = 'OPEN_PANEL';
export const ANALYZE = 'ANALYZE';
export const ANALYSIS_RESULT = 'ANALYSIS_RESULT';
export const IMPORT_BURP = 'IMPORT_BURP';
export const BURP_IMPORTED = 'BURP_IMPORTED';
export const CRAWL_SITE = 'CRAWL_SITE';
export const CRAWL_RESULT = 'CRAWL_RESULT';
export const GET_TRAFFIC = 'GET_TRAFFIC';
export const TRAFFIC_RESULT = 'TRAFFIC_RESULT';

export const MESSAGE_TYPES = Object.freeze({
  SCAN_PAGE,
  SCAN_RESULT,
  GET_STATE,
  STATE,
  OPEN_PANEL,
  ANALYZE,
  ANALYSIS_RESULT,
  IMPORT_BURP,
  BURP_IMPORTED,
  CRAWL_SITE,
  CRAWL_RESULT,
  GET_TRAFFIC,
  TRAFFIC_RESULT,
});

/** Return the extension API namespace (Firefox `browser` or Chrome `chrome`). */
export function br() {
  return globalThis.browser || globalThis.chrome;
}

/**
 * Send a message to the background page/service worker.
 * Resolves with the response, rejects on runtime errors.
 */
export function sendToBackground(msg) {
  const api = br();
  if (!api?.runtime?.sendMessage) return Promise.resolve(undefined);

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (value, error) => {
      if (settled) return;
      settled = true;
      if (error) {
        const message = error?.message ? String(error.message) : String(error);
        reject(error instanceof Error ? error : new Error(message));
      } else {
        resolve(value);
      }
    };

    const callback = (response) => {
      const lastError = api.runtime?.lastError;
      finish(response, lastError ? lastError : null);
    };

    let result;
    try {
      result = api.runtime.sendMessage(msg, callback);
    } catch {
      // Firefox's promise-only API may reject a callback argument.
      try {
        result = api.runtime.sendMessage(msg);
      } catch (error) {
        finish(undefined, error);
        return;
      }
    }

    if (result && typeof result.then === 'function') {
      result.then(
        (value) => finish(value, null),
        (error) => finish(undefined, error),
      );
    }
    // Chrome returns undefined and invokes `callback` asynchronously.
  });
}

export default { br, sendToBackground, MESSAGE_TYPES };
