/**
 * HTML page for the local rules-picker UI. Everything is inlined except the
 * logo, which the server serves from the local-only /logo.png route - no
 * external CDNs or network calls.
 */
export interface RuleRow {
    id: string;
    title: string;
    severity: string;
    category: string;
    source: 'builtin' | 'external';
    disabled: boolean;
}
export interface Allowlists {
    allowedDomains: string[];
    allowedValues: string[];
    allowedPatterns: string[];
}
export declare function renderPage(rules: RuleRow[], allowlists: Allowlists, token: string, configPath: string, isGlobal: boolean): string;
