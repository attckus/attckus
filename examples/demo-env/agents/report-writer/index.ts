// Report writer: summarises weekly analytics into a report. Read-only by design.
import Anthropic from '@anthropic-ai/sdk'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'

const anthropic = new Anthropic()
export async function weeklyReport(mcp: Client) {
  // queries the analytics database through the postgres MCP server
}
