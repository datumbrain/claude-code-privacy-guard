#!/usr/bin/env node
/**
 * claude-code-privacy-guard CLI
 *
 * Usage: npx claude-code-privacy-guard rules
 */
import { startRulesServer } from './server.js';
const [, , command] = process.argv;
switch (command) {
    case 'rules':
    case undefined:
        startRulesServer().catch((error) => {
            console.error('Failed to start rules editor:', error);
            process.exit(1);
        });
        break;
    default:
        console.error(`Unknown command: ${command}\n\nUsage: claude-code-privacy-guard rules`);
        process.exit(1);
}
