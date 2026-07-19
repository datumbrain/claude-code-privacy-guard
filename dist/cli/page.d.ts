/**
 * Self-contained HTML page for the local rules-picker UI. No external
 * assets/CDNs - everything is inlined so it works fully offline.
 */
export interface RuleRow {
    id: string;
    title: string;
    severity: string;
    category: string;
    source: 'builtin' | 'external';
    disabled: boolean;
}
export declare function renderPage(rules: RuleRow[], token: string, configPath: string, isGlobal: boolean): string;
//# sourceMappingURL=page.d.ts.map