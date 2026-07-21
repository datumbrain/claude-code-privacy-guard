/**
 * Local-only HTTP server for the rules-picker UI. Binds to loopback only,
 * requires a random per-run token on the save endpoint (defense in depth -
 * the JSON content-type already blocks simple cross-origin POSTs), and
 * shuts itself down after a period of inactivity (saving keeps it alive so
 * you can toggle and save again without restarting).
 */
export declare function startRulesServer(): Promise<void>;
