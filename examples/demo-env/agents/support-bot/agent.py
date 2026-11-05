"""Support bot: answers customer questions, looks up orders, posts escalations to Slack."""
from langgraph.prebuilt import create_react_agent
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

client = OpenAI()

# Tools come from the MCP servers in mcp.json (fetch, slack) plus boto3 calls
# against the orders bucket using the pod's IRSA role.
