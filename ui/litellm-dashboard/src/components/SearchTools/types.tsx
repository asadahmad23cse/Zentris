export interface SearchToolZentrisParams {
  search_provider: string;
  api_key?: string;
  api_base?: string;
  timeout?: number;
  max_retries?: number;
  [key: string]: any;
}

export interface SearchToolInfo {
  description?: string;
  [key: string]: any;
}

export interface SearchTool {
  search_tool_id?: string;
  search_tool_name: string;
  Zentris_params: SearchToolZentrisParams;
  search_tool_info?: SearchToolInfo;
  created_at?: string;
  updated_at?: string;
  is_from_config?: boolean;
}

export interface SearchToolsResponse {
  search_tools: SearchTool[];
}

export interface AvailableSearchProvider {
  provider_name: string;
  ui_friendly_name: string;
}

export interface AvailableSearchProvidersResponse {
  providers: AvailableSearchProvider[];
}




