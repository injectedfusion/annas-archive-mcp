use std::sync::Arc;

use annas_archive_api::{AnnasArchiveClient, SearchOptions};
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    tool, tool_handler, tool_router,
};

use crate::tools::{DetailsParams, DownloadParams, SearchParams};

#[derive(Clone)]
pub struct AnnasArchiveServer {
    client: Arc<AnnasArchiveClient>,
    api_key_for_sanitize: Option<String>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

fn sanitize_output(text: &str, key: &Option<String>) -> String {
    let Some(key) = key else {
        return text.to_string();
    };
    if key.len() < 5 {
        return text.to_string();
    }
    text.replace(key.as_str(), "[REDACTED]")
}

fn sanitized_error(e: impl std::fmt::Display, key: &Option<String>) -> CallToolResult {
    let msg = sanitize_output(&e.to_string(), key);
    CallToolResult::error(vec![Content::text(msg)])
}

fn sanitized_success(json: String, key: &Option<String>) -> CallToolResult {
    let msg = sanitize_output(&json, key);
    CallToolResult::success(vec![Content::text(msg)])
}

impl AnnasArchiveServer {
    pub fn new(api_key: Option<String>, domains: Option<Vec<String>>) -> Self {
        Self {
            client: Arc::new(AnnasArchiveClient::new(api_key.clone(), domains)),
            api_key_for_sanitize: api_key,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_handler]
impl ServerHandler for AnnasArchiveServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Access Anna's Archive to search for and get information about books, papers, magazines, comics, and other documents. Use get_download_url only if you have an API key configured.".to_string()
            ),
        }
    }
}

#[tool_router]
impl AnnasArchiveServer {
    #[tool(
        description = "Search Anna's Archive for books, papers, magazines, comics, and other documents"
    )]
    async fn search(
        &self,
        Parameters(params): Parameters<SearchParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let options = SearchOptions::new(&params.query);
        let options = if let Some(page) = params.page {
            options.with_page(page)
        } else {
            options
        };

        match self.client.search(options).await {
            Ok(response) => {
                let json = serde_json::to_string_pretty(&response).map_err(|e| {
                    rmcp::ErrorData::internal_error(format!("Serialize error: {e}"), None)
                })?;
                Ok(sanitized_success(json, &self.api_key_for_sanitize))
            }
            Err(e) => Ok(sanitized_error(
                format!("Search failed: {e}"),
                &self.api_key_for_sanitize,
            )),
        }
    }

    #[tool(description = "Get detailed metadata for an item by its MD5 hash")]
    async fn get_details(
        &self,
        Parameters(params): Parameters<DetailsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self.client.get_details(&params.md5).await {
            Ok(details) => {
                let json = serde_json::to_string_pretty(&details).map_err(|e| {
                    rmcp::ErrorData::internal_error(format!("Serialize error: {e}"), None)
                })?;
                Ok(sanitized_success(json, &self.api_key_for_sanitize))
            }
            Err(e) => Ok(sanitized_error(
                format!("Failed to get details: {e}"),
                &self.api_key_for_sanitize,
            )),
        }
    }

    #[tool(
        description = "Get a fast download URL for an item (requires ANNAS_ARCHIVE_API_KEY environment variable)"
    )]
    async fn get_download_url(
        &self,
        Parameters(params): Parameters<DownloadParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .client
            .get_download_url(&params.md5, params.path_index, params.domain_index)
            .await
        {
            Ok(info) => {
                let json = serde_json::to_string_pretty(&info).map_err(|e| {
                    rmcp::ErrorData::internal_error(format!("Serialize error: {e}"), None)
                })?;
                Ok(sanitized_success(json, &self.api_key_for_sanitize))
            }
            Err(e) => Ok(sanitized_error(
                format!("Failed to get download URL: {e}"),
                &self.api_key_for_sanitize,
            )),
        }
    }
}
