#!/usr/bin/env python3
"""
Generic MCP Server that dynamically generates tools based on YAML configuration.
Handles token authentication and creates MCP tools for API endpoints.
"""

import json
import logging
import yaml
import requests
import asyncio
from typing import Dict, Any, List, Optional
from fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GenericMCPServer:
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = config_file
        self.config: Dict[str, Any] = {}
        self.access_token: Optional[str] = None
        self.mcp = FastMCP("Generic MCP Server")

        # Load configuration
        self.load_config()

        # Fetch authentication token
        self.fetch_token()

        # Create dynamic tools
        self.create_dynamic_tools()

    def load_config(self) -> None:
        """Load and parse the YAML configuration file."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as file:
                self.config = yaml.safe_load(file)
            logger.info(f"Loaded configuration from {self.config_file}")
        except FileNotFoundError:
            logger.error(f"Configuration file {self.config_file} not found")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            raise

    def fetch_token(self) -> None:
        """Fetch authentication token using the 'token' tool configuration."""
        try:
            # Find the token tool configuration
            token_tool = None
            for tool in self.config.get('tools_info', []):
                if tool.get('name') == 'token':
                    token_tool = tool
                    break

            if not token_tool:
                logger.error("No 'token' tool found in configuration")
                return

            # Build request parameters
            headers = {}
            form_data = {}

            for param in token_tool.get('param_info', []):
                name = param.get('name')
                value = param.get('value', '')
                group = param.get('group')

                # Replace template variables
                if '{{username}}' in value:
                    value = value.replace('{{username}}', self.config.get('api_info', {}).get('username', ''))
                if '{{password}}' in value:
                    value = value.replace('{{password}}', self.config.get('api_info', {}).get('password', ''))

                if group == 'header':
                    headers[name] = value
                elif group == 'data-urlencode':
                    form_data[name] = value

            # Make the token request
            response = requests.post(
                token_tool.get('url'),
                headers=headers,
                data=form_data,
                timeout=30
            )
            response.raise_for_status()

            # Extract access token from response
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            
            if self.access_token:
                logger.info("Successfully fetched access token")
            else:
                logger.error("Access token not found in response")

        except requests.RequestException as e:
            logger.error(f"Error fetching token: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing token response: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching token: {e}")

    def create_dynamic_tools(self) -> None:
        """Create MCP tools dynamically based on configuration."""
        tools_info = self.config.get('tools_info', [])

        for tool_config in tools_info:
            tool_name = tool_config.get('name')

            # Skip the token tool as it's used for authentication only
            if tool_name == 'token':
                continue

            # Create the tool
            self.create_mcp_tool(tool_config)

    def create_mcp_tool(self, tool_config: Dict[str, Any]) -> None:
        """Create a single MCP tool from configuration."""
        tool_name = tool_config.get('name')
        tool_description = tool_config.get('description', '')
        tool_url = tool_config.get('url')
        tool_method = tool_config.get('method', 'GET')
        param_info = tool_config.get('param_info', [])

        # Determine tool parameters (exclude headers)
        tool_params = []
        for param in param_info:
            group = param.get('group')
            param_name = param.get('name')

            # Only include non-header parameters as tool inputs
            if group in ['data-raw', 'param']:
                tool_params.append(param_name)

        # Create dynamic function with appropriate parameters
        def create_tool_function(config, params_list):
            """Factory function to create tool function with proper closure."""
            if params_list:
                # Create function with parameters dynamically
                def dynamic_tool(**kwargs) -> str:
                    return self.execute_tool_request(config, kwargs)

                # Set the function signature dynamically
                import inspect
                sig_params = [
                    inspect.Parameter(
                        name=param_name,
                        kind=inspect.Parameter.KEYWORD_ONLY,
                        annotation=str
                    )
                    for param_name in params_list
                ]
                sig_params.append(
                    inspect.Parameter('return', kind=inspect.Parameter.POSITIONAL_ONLY, annotation=str)
                )
                dynamic_tool.__signature__ = inspect.Signature(sig_params[:-1])
                dynamic_tool.__annotations__ = {param: str for param in params_list}
                dynamic_tool.__annotations__['return'] = str

                return dynamic_tool
            else:
                # No parameters - simpler function
                def dynamic_tool() -> str:
                    return self.execute_tool_request(config, {})
                return dynamic_tool

        # Create and register the tool
        tool_function = create_tool_function(tool_config, tool_params)
        tool_function.__name__ = tool_name.lower().replace(' ', '_') + '_tool'

        # Register with MCP
        self.mcp.tool(description=tool_description)(tool_function)

        logger.info(f"Created MCP tool: {tool_name} with parameters: {tool_params}")

    def execute_tool_request(self, tool_config: Dict[str, Any], params: Dict[str, Any]) -> str:
        """Execute the HTTP request for a tool."""
        try:
            url = tool_config.get('url')
            method = tool_config.get('method', 'GET')
            param_info = tool_config.get('param_info', [])

            # Build request components
            headers = {}
            request_body = {}
            url_params = {}
            form_data = {}

            for param in param_info:
                param_name = param.get('name')
                param_value = param.get('value', '')
                group = param.get('group')

                # Replace template variables
                if '{{token}}' in param_value and self.access_token:
                    param_value = param_value.replace('{{token}}', self.access_token)

                # Get parameter value from tool inputs
                if group in ['data-raw', 'param'] and param_name in params:
                    param_value = params[param_name]

                # Assign to appropriate request component
                if group == 'header':
                    headers[param_name] = param_value
                elif group == 'data-raw':
                    request_body[param_name] = param_value
                elif group == 'param':
                    url_params[param_name] = param_value
                elif group == 'data-urlencode':
                    form_data[param_name] = param_value

            # Build final URL with path parameters
            final_url = url
            for param_name, param_value in url_params.items():
                final_url = final_url.replace(f"/{param_name}", f"/{param_value}")

            # Make the request
            request_kwargs = {
                'url': final_url,
                'headers': headers,
                'timeout': 30
            }

            # Add body data based on content type
            content_type = headers.get('Content-Type', '')
            if 'application/json' in content_type and request_body:
                request_kwargs['json'] = request_body
            elif 'application/x-www-form-urlencoded' in content_type:
                if request_body:
                    request_kwargs['data'] = request_body
                elif form_data:
                    request_kwargs['data'] = form_data
            elif request_body:
                request_kwargs['json'] = request_body

            response = requests.request(method, **request_kwargs)
            response.raise_for_status()

            # Return JSON response as string
            try:
                return json.dumps(response.json(), indent=2)
            except json.JSONDecodeError:
                return response.text

        except requests.RequestException as e:
            error_msg = f"Request failed: {e}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            logger.error(error_msg)
            return json.dumps({"error": error_msg})

    async def run_async(self):
        """Run the MCP server asynchronously with HTTP transport."""
        logger.info(f"Starting MCP server: {self.config.get('name', 'Generic MCP Server')}")
        await self.mcp.run_async(transport="http", host="0.0.0.0", port=8080)

def main():
    """Main entry point."""
    try:
        server = GenericMCPServer()
        asyncio.run(server.run_async())
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        raise

if __name__ == "__main__":
    main()