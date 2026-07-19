#!/usr/bin/env node

/**
 * Claude Code Privacy Guard MCP Server
 *
 * Privacy guard plugin for Claude Code that prevents PII and secrets
 * from leaking into AI prompts.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { fileURLToPath } from 'url';

import { PrivacyScanner } from './scanner/engine.js';
import { BUILTIN_RULES, loadExternalRulesFromJson } from './scanner/detectors.js';
import { Redactor } from './redactor/masker.js';
import { ConfigLoader } from './config/loader.js';
import { DetectionRule } from './types/findings.js';

/**
 * Main MCP server
 */
class PrivacyGuardServer {
  private server: Server;
  private scanner: PrivacyScanner;
  private config: ReturnType<ConfigLoader['getConfig']>;
  private allRules: DetectionRule[];
  private disabledRules: Set<string>;

  constructor() {
    this.server = new Server(
      {
        name: 'claude-code-privacy-guard',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Load configuration
    const configPath = ConfigLoader.findConfig();
    const configLoader = new ConfigLoader(configPath || undefined);
    this.config = configLoader.getConfig();

    // Initialize scanner with built-in + external JSON rules
    const defaultExternalRulesPath = fileURLToPath(new URL('../data/regex_list_1.json', import.meta.url));
    const externalRulesPath = this.config.externalRulesJsonPath || defaultExternalRulesPath;
    const externalRules = loadExternalRulesFromJson(externalRulesPath, {
      codingOnly: this.config.externalRulesMode !== 'all',
    });
    this.allRules = [...BUILTIN_RULES, ...externalRules];
    this.disabledRules = new Set(this.config.disabledRules);
    const activeRules = this.allRules.filter((rule) => !this.disabledRules.has(rule.id));
    this.scanner = new PrivacyScanner(activeRules);

    this.setupHandlers();

    // Error handling
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'scan_prompt',
          description: 'Scan text for PII, secrets, and sensitive data before sending to Claude',
          inputSchema: {
            type: 'object',
            properties: {
              text: {
                type: 'string',
                description: 'The prompt text to scan for sensitive data',
              },
            },
            required: ['text'],
          },
        },
        {
          name: 'redact_prompt',
          description: 'Scan and automatically redact sensitive data from text',
          inputSchema: {
            type: 'object',
            properties: {
              text: {
                type: 'string',
                description: 'The text to scan and redact',
              },
            },
            required: ['text'],
          },
        },
        {
          name: 'list_rules',
          description: 'List every detection rule (built-in and external) with its ID, title, severity, category, and whether it is currently disabled via disabledRules',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      switch (name) {
        case 'scan_prompt': {
          const { text } = args as { text: string };
          const result = this.scanner.scan(text);

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  summary: Redactor.summarize(result),
                  findings: result.findings.length,
                  riskScore: result.riskScore,
                  hasHighRisk: result.hasHighRisk,
                  hasCriticalRisk: result.hasCriticalRisk,
                  details: result.summary,
                }, null, 2),
              },
            ],
          };
        }

        case 'redact_prompt': {
          const { text } = args as { text: string };
          const result = this.scanner.scan(text);

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  originalLength: result.originalText.length,
                  redactedText: result.redactedText,
                  findingsCount: result.findings.length,
                  summary: Redactor.summarize(result),
                }, null, 2),
              },
            ],
          };
        }

        case 'list_rules': {
          const rules = this.allRules.map((rule) => ({
            id: rule.id,
            title: rule.title,
            severity: rule.severity,
            category: rule.category,
            source: rule.id.startsWith('external-') ? 'external' : 'builtin',
            disabled: this.disabledRules.has(rule.id),
          }));

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ rules, total: rules.length, disabledCount: this.disabledRules.size }, null, 2),
              },
            ],
          };
        }

        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Claude Code Privacy Guard MCP server running on stdio');
  }
}

// Start the server
const server = new PrivacyGuardServer();
server.run().catch(console.error);
