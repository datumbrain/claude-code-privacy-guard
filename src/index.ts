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

/**
 * Main MCP server
 */
class PrivacyGuardServer {
  private server: Server;
  private scanner: PrivacyScanner;
  private config: ReturnType<ConfigLoader['getConfig']>;

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
    const disabledRules = new Set(this.config.disabledRules);
    const activeRules = [...BUILTIN_RULES, ...externalRules].filter((rule) => !disabledRules.has(rule.id));
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
