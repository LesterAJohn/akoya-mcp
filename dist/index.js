import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod/v4';
function buildServer() {
    const server = new McpServer({ name: 'akoya-mcp', version: '0.1.0' });
    server.registerTool('akoya_connection_info', {
        description: 'Return the local Akoya MCP starter configuration.',
        inputSchema: z.object({})
    }, async () => ({
        content: [
            {
                type: 'text',
                text: JSON.stringify({
                    service: 'akoya',
                    mode: 'local-starter',
                    environment: {
                        AKOYA_BASE_URL: process.env.AKOYA_BASE_URL ?? null,
                        AKOYA_CLIENT_ID: process.env.AKOYA_CLIENT_ID ? 'set' : null,
                        AKOYA_CLIENT_SECRET: process.env.AKOYA_CLIENT_SECRET ? 'set' : null
                    }
                }, null, 2)
            }
        ]
    }));
    return server;
}
serveStdio(buildServer);
