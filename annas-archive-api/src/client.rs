use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use reqwest::{Client, cookie::Jar};
use tokio::sync::Mutex;

use crate::error::Error;
use crate::scraper::parse_search_results;
use crate::types::{
    DownloadInfo, DownloadSource, Identifiers, IpfsInfo, ItemDetails, SearchOptions, SearchResponse,
};

const DEFAULT_DOMAINS: &[&str] = &[
    "annas-archive.pk",
    "annas-archive.gd",
    "annas-archive.gl",
];

const NOT_AUTHENTICATED: usize = usize::MAX;
const MAX_AUTH_FAILURES_BEFORE_BLACKLIST: u32 = 5;
const MAX_BACKOFF_SECS: u64 = 60;

struct DomainState {
    consecutive_failures: u32,
    last_failure: Option<Instant>,
    blacklisted: bool,
    retry_after: Option<Duration>,
}

impl DomainState {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            last_failure: None,
            blacklisted: false,
            retry_after: None,
        }
    }

    fn record_failure(&mut self, retry_after: Option<Duration>) {
        self.consecutive_failures += 1;
        self.last_failure = Some(Instant::now());
        self.retry_after = retry_after;
        if self.consecutive_failures >= MAX_AUTH_FAILURES_BEFORE_BLACKLIST {
            self.blacklisted = true;
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.last_failure = None;
        self.retry_after = None;
    }

    fn backoff_remaining(&self) -> Option<Duration> {
        let last = self.last_failure?;
        let elapsed = last.elapsed();

        if let Some(retry_after) = self.retry_after {
            return retry_after.checked_sub(elapsed);
        }

        let backoff_secs = (1u64 << self.consecutive_failures.min(6)).min(MAX_BACKOFF_SECS);
        let backoff = Duration::from_secs(backoff_secs);
        backoff.checked_sub(elapsed)
    }
}

fn resolve_domains(domains: Option<Vec<String>>) -> Vec<String> {
    if let Some(d) = domains {
        if !d.is_empty() {
            return d;
        }
    }
    if let Ok(env_val) = std::env::var("ANNAS_ARCHIVE_DOMAINS") {
        let parsed: Vec<String> = env_val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    DEFAULT_DOMAINS.iter().map(|s| s.to_string()).collect()
}

fn validate_api_key(key: &str) {
    let trimmed = key.trim();
    assert!(
        !trimmed.is_empty(),
        "ANNAS_ARCHIVE_API_KEY is empty"
    );
    assert!(
        trimmed.len() >= 5 && trimmed.len() <= 200,
        "ANNAS_ARCHIVE_API_KEY length {} is outside valid range 5-200",
        trimmed.len()
    );
    assert!(
        trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "ANNAS_ARCHIVE_API_KEY contains invalid characters (only alphanumeric, hyphens, underscores allowed)"
    );
}

pub struct AnnasArchiveClient {
    client: Client,
    api_key: Option<String>,
    domains: Vec<String>,
    #[allow(dead_code)]
    cookie_jar: Arc<Jar>,
    authenticated_domain_idx: AtomicUsize,
    domain_states: Mutex<HashMap<String, DomainState>>,
}

impl AnnasArchiveClient {
    pub fn new(api_key: Option<String>, domains: Option<Vec<String>>) -> Self {
        if let Some(ref key) = api_key {
            validate_api_key(key);
        }

        let cookie_jar = Arc::new(Jar::default());

        let client = Client::builder()
            .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
            .cookie_provider(cookie_jar.clone())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client");

        let resolved_domains = resolve_domains(domains);
        let domain_states: HashMap<String, DomainState> = resolved_domains
            .iter()
            .map(|d| (d.clone(), DomainState::new()))
            .collect();

        Self {
            client,
            api_key,
            domains: resolved_domains,
            cookie_jar,
            authenticated_domain_idx: AtomicUsize::new(NOT_AUTHENTICATED),
            domain_states: Mutex::new(domain_states),
        }
    }

    fn is_allowed_url(&self, url: &str) -> bool {
        if !url.starts_with("https://") {
            return false;
        }
        let host = url
            .strip_prefix("https://")
            .and_then(|rest| rest.split('/').next())
            .and_then(|host_port| host_port.split(':').next())
            .unwrap_or("");
        self.domains.iter().any(|d| d == host)
    }

    fn authenticated_domain(&self) -> Option<&str> {
        let idx = self.authenticated_domain_idx.load(Ordering::SeqCst);
        if idx == NOT_AUTHENTICATED {
            return None;
        }
        self.domains.get(idx).map(|s| s.as_str())
    }

    async fn check_domain_available(&self, domain: &str) -> Result<(), Error> {
        let states = self.domain_states.lock().await;
        if let Some(state) = states.get(domain) {
            if state.blacklisted {
                return Err(Error::DomainBlacklisted(domain.to_string()));
            }
            if let Some(remaining) = state.backoff_remaining() {
                tokio::time::sleep(remaining).await;
            }
        }
        Ok(())
    }

    fn parse_retry_after(response: &reqwest::Response) -> Option<Duration> {
        response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|secs| Duration::from_secs(secs.min(MAX_BACKOFF_SECS)))
    }

    async fn record_auth_failure(&self, domain: &str, response: Option<&reqwest::Response>) {
        let retry_after = response.and_then(Self::parse_retry_after);
        let mut states = self.domain_states.lock().await;
        if let Some(state) = states.get_mut(domain) {
            state.record_failure(retry_after);
        }
    }

    async fn record_auth_success(&self, domain: &str) {
        let mut states = self.domain_states.lock().await;
        if let Some(state) = states.get_mut(domain) {
            state.record_success();
        }
    }

    async fn authenticate(&self) -> Result<(), Error> {
        let api_key = self.api_key.as_ref().ok_or(Error::MissingApiKey)?;

        for (idx, domain) in self.domains.iter().enumerate() {
            if let Err(e) = self.check_domain_available(domain).await {
                if matches!(e, Error::DomainBlacklisted(_)) {
                    continue;
                }
            }

            let url = format!("https://{domain}/account/");
            if !self.is_allowed_url(&url) {
                continue;
            }

            let response = self
                .client
                .post(&url)
                .form(&[("key", api_key.as_str())])
                .send()
                .await;

            match response {
                Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
                    self.authenticated_domain_idx.store(idx, Ordering::SeqCst);
                    self.record_auth_success(domain).await;
                    return Ok(());
                }
                Ok(resp) if resp.status().as_u16() == 403 || resp.status().as_u16() == 429 => {
                    self.record_auth_failure(domain, Some(&resp)).await;
                    continue;
                }
                Ok(resp) if resp.status().is_client_error() => {
                    return Err(Error::Api {
                        message: "Invalid secret key".to_string(),
                    });
                }
                Ok(resp) => {
                    self.record_auth_failure(domain, Some(&resp)).await;
                    continue;
                }
                Err(_) => {
                    self.record_auth_failure(domain, None).await;
                    continue;
                }
            }
        }

        Err(Error::AllDomainsFailed {
            message: "Failed to authenticate with any domain".to_string(),
        })
    }

    async fn ensure_authenticated(&self) -> Result<(), Error> {
        if self.authenticated_domain_idx.load(Ordering::SeqCst) == NOT_AUTHENTICATED {
            self.authenticate().await?;
        }
        Ok(())
    }

    async fn fetch_with_failover(&self, path: &str) -> Result<String, Error> {
        let mut last_error = None;

        for domain in &self.domains {
            if self.check_domain_available(domain).await.is_err() {
                continue;
            }

            let url = format!("https://{domain}{path}");
            if !self.is_allowed_url(&url) {
                continue;
            }

            match self.client.get(&url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return response.text().await.map_err(Error::from_reqwest);
                    } else if response.status().as_u16() == 403
                        || response.status().as_u16() == 429
                    {
                        self.record_auth_failure(domain, Some(&response)).await;
                        last_error = Some(Error::Http {
                            status: response.status().as_u16(),
                        });
                    } else if response.status().is_client_error() {
                        return Err(Error::Http {
                            status: response.status().as_u16(),
                        });
                    } else {
                        last_error = Some(Error::Http {
                            status: response.status().as_u16(),
                        });
                    }
                }
                Err(e) => {
                    last_error = Some(Error::from_reqwest(e));
                }
            }
        }

        Err(last_error.unwrap_or(Error::AllDomainsFailed {
            message: "No domains available".to_string(),
        }))
    }

    pub async fn search(&self, options: SearchOptions) -> Result<SearchResponse, Error> {
        let page = options.page.unwrap_or(1);
        let query = urlencoding::encode(&options.query);
        let path = format!("/search?q={query}&page={page}");

        let html = self.fetch_with_failover(&path).await?;
        let (results, has_more) = parse_search_results(&html)?;

        Ok(SearchResponse {
            results,
            page,
            has_more,
        })
    }

    pub async fn get_details(&self, md5: &str) -> Result<ItemDetails, Error> {
        self.ensure_authenticated().await?;

        let path = format!("/db/aarecord_elasticsearch/md5:{md5}.json");

        if let Some(domain) = self.authenticated_domain() {
            let url = format!("https://{domain}{path}");
            if self.is_allowed_url(&url) {
                match self.client.get(&url).send().await {
                    Ok(response) if response.status().is_success() => {
                        let json_str = response.text().await.map_err(Error::from_reqwest)?;
                        return parse_json_details(&json_str, md5);
                    }
                    Ok(response)
                        if response.status().as_u16() == 403
                            || response.status().as_u16() == 429 =>
                    {
                        self.record_auth_failure(domain, Some(&response)).await;
                        self.authenticated_domain_idx
                            .store(NOT_AUTHENTICATED, Ordering::SeqCst);
                        self.authenticate().await?;

                        if let Some(domain) = self.authenticated_domain() {
                            let url = format!("https://{domain}{path}");
                            if self.is_allowed_url(&url) {
                                if let Ok(resp) = self.client.get(&url).send().await
                                    && resp.status().is_success()
                                {
                                    let json_str =
                                        resp.text().await.map_err(Error::from_reqwest)?;
                                    return parse_json_details(&json_str, md5);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut last_error = None;
        for domain in &self.domains {
            if self.check_domain_available(domain).await.is_err() {
                continue;
            }

            let url = format!("https://{domain}{path}");
            if !self.is_allowed_url(&url) {
                continue;
            }

            match self.client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {
                    let json_str = response.text().await.map_err(Error::from_reqwest)?;
                    return parse_json_details(&json_str, md5);
                }
                Ok(response) if response.status().is_client_error() => {
                    return Err(Error::Http {
                        status: response.status().as_u16(),
                    });
                }
                Ok(response) => {
                    last_error = Some(Error::Http {
                        status: response.status().as_u16(),
                    });
                }
                Err(e) => {
                    last_error = Some(Error::from_reqwest(e));
                }
            }
        }

        Err(last_error.unwrap_or(Error::AllDomainsFailed {
            message: "Failed to get details from any domain".to_string(),
        }))
    }

    pub async fn get_download_url(
        &self,
        md5: &str,
        path_index: Option<u32>,
        domain_index: Option<u32>,
    ) -> Result<DownloadInfo, Error> {
        let api_key = self.api_key.as_ref().ok_or(Error::MissingApiKey)?;

        let path_idx = path_index.unwrap_or(0);
        let domain_idx = domain_index.unwrap_or(0);

        self.ensure_authenticated().await?;
        let auth_domain = self.authenticated_domain().ok_or(Error::AllDomainsFailed {
            message: "No authenticated domain available".to_string(),
        })?;

        self.check_domain_available(auth_domain).await?;

        let url = format!(
            "https://{auth_domain}/dyn/api/fast_download.json?md5={md5}&path_index={path_idx}&domain_index={domain_idx}&key={api_key}"
        );

        if !self.is_allowed_url(&url) {
            return Err(Error::DomainNotAllowed(auth_domain.to_string()));
        }

        let response = self.client.get(&url).send().await.map_err(Error::from_reqwest)?;

        if response.status().as_u16() == 403 || response.status().as_u16() == 429 {
            self.record_auth_failure(auth_domain, Some(&response)).await;
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();

            if body.contains("no_membership") {
                return Err(Error::Api {
                    message: "No active membership for this API key".to_string(),
                });
            }
            if body.contains("invalid") {
                return Err(Error::Api {
                    message: "Invalid API key".to_string(),
                });
            }

            return Err(Error::Http { status });
        }

        #[derive(serde::Deserialize)]
        struct ApiResponse {
            download_url: Option<String>,
            error: Option<String>,
        }

        let api_response: ApiResponse = response.json().await.map_err(Error::from_reqwest)?;

        if let Some(error) = api_response.error {
            return Err(Error::Api { message: error });
        }

        let download_url = api_response.download_url.ok_or(Error::Api {
            message: "No download URL in response".to_string(),
        })?;

        Ok(DownloadInfo { download_url })
    }
}

fn parse_json_details(json_str: &str, md5: &str) -> Result<ItemDetails, Error> {
    let json_str = json_str.trim();
    let json_str = if json_str.starts_with('"') && json_str.ends_with('"') {
        serde_json::from_str::<String>(json_str).map_err(|e| Error::Parse {
            message: format!("Failed to parse outer JSON: {e}"),
        })?
    } else {
        json_str.to_string()
    };

    let data: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| Error::Parse {
        message: format!("Failed to parse JSON: {e}"),
    })?;

    if let Some(error) = data.get("error").and_then(|v| v.as_str()) {
        return Err(Error::Api {
            message: error.to_string(),
        });
    }

    let file_data = data.get("file_unified_data").ok_or_else(|| Error::Parse {
        message: "Missing file_unified_data".to_string(),
    })?;

    let title = file_data
        .get("title_best")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();

    let author = file_data
        .get("author_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let format = file_data
        .get("extension_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_uppercase());

    let size_bytes = file_data.get("filesize_best").and_then(|v| v.as_u64());

    let size = size_bytes.map(format_filesize);

    let language = file_data
        .get("language_codes")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let publisher = file_data
        .get("publisher_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let year = file_data
        .get("year_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let description = file_data
        .get("stripped_description_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let cover_url = file_data
        .get("cover_url_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let content_type = file_data
        .get("content_type_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let original_filename = file_data
        .get("original_filename_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let added_date = file_data
        .get("added_date_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let pages = file_data
        .get("pages_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let edition = file_data
        .get("edition_varia_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let series = file_data
        .get("series_best")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let identifiers = parse_identifiers(file_data.get("identifiers_unified"));

    let categories = parse_string_list_from_object(file_data.get("classifications_unified"));

    let subjects = parse_string_list_from_object(
        file_data
            .get("classifications_unified")
            .and_then(|c| c.get("collection")),
    )
    .or_else(|| {
        file_data
            .get("classifications_unified")
            .and_then(|c| c.as_object())
            .and_then(|obj| {
                obj.iter()
                    .find(|(k, _)| k.contains("subject"))
                    .and_then(|(_, v)| {
                        v.as_array().map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                    })
            })
    });

    let ipfs_cids = parse_ipfs_infos(file_data.get("ipfs_infos"));

    let additional = data.get("additional");

    let download_sources = parse_download_sources(additional);
    let torrent_paths = parse_torrent_paths(additional);

    Ok(ItemDetails {
        md5: md5.to_string(),
        title,
        author,
        format,
        size,
        size_bytes,
        language,
        publisher,
        year,
        description,
        cover_url,
        content_type,
        original_filename,
        added_date,
        pages,
        edition,
        series,
        identifiers,
        categories,
        subjects,
        ipfs_cids,
        download_sources,
        torrent_paths,
    })
}

fn parse_identifiers(value: Option<&serde_json::Value>) -> Option<Identifiers> {
    let obj = value?.as_object()?;

    let get_string_array = |key: &str| -> Option<Vec<String>> {
        obj.get(key).and_then(|v| {
            v.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
        })
    };

    let get_first_string = |key: &str| -> Option<String> {
        obj.get(key)
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(String::from)
    };

    let identifiers = Identifiers {
        isbn10: get_string_array("isbn10"),
        isbn13: get_string_array("isbn13"),
        doi: get_string_array("doi"),
        asin: get_string_array("asin"),
        sha1: get_first_string("sha1"),
        sha256: get_first_string("sha256"),
        crc32: get_first_string("crc32"),
        blake2b: get_first_string("blake2b"),
        open_library: get_string_array("ol"),
        google_books: get_string_array("googlebookid"),
        goodreads: get_string_array("goodreads"),
        amazon: get_string_array("amazon"),
    };

    if identifiers.isbn10.is_some()
        || identifiers.isbn13.is_some()
        || identifiers.doi.is_some()
        || identifiers.asin.is_some()
        || identifiers.sha1.is_some()
        || identifiers.sha256.is_some()
        || identifiers.open_library.is_some()
        || identifiers.google_books.is_some()
    {
        Some(identifiers)
    } else {
        None
    }
}

fn parse_string_list_from_object(value: Option<&serde_json::Value>) -> Option<Vec<String>> {
    let obj = value?.as_object()?;
    let mut result = Vec::new();

    for (key, val) in obj {
        if key == "collection" || key.starts_with('_') {
            continue;
        }
        if let Some(arr) = val.as_array() {
            for item in arr {
                if let Some(s) = item.as_str()
                    && !s.is_empty()
                    && !result.contains(&s.to_string())
                {
                    result.push(s.to_string());
                }
            }
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn parse_ipfs_infos(value: Option<&serde_json::Value>) -> Option<Vec<IpfsInfo>> {
    let arr = value?.as_array()?;
    let infos: Vec<IpfsInfo> = arr
        .iter()
        .filter_map(|v| {
            let obj = v.as_object()?;
            let cid = obj.get("ipfs_cid")?.as_str()?.to_string();
            let from = obj
                .get("from")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            Some(IpfsInfo { cid, from })
        })
        .collect();

    if infos.is_empty() { None } else { Some(infos) }
}

fn parse_download_sources(additional: Option<&serde_json::Value>) -> Option<Vec<DownloadSource>> {
    let obj = additional?.as_object()?;
    let mut sources = Vec::new();

    if let Some(urls) = obj.get("download_urls").and_then(|v| v.as_array()) {
        for url in urls {
            if let Some(url_str) = url.as_str() {
                sources.push(DownloadSource {
                    name: "direct".to_string(),
                    url: url_str.to_string(),
                });
            }
        }
    }

    if let Some(urls) = obj.get("ipfs_urls").and_then(|v| v.as_array()) {
        for url in urls {
            if let Some(url_str) = url.as_str() {
                sources.push(DownloadSource {
                    name: "ipfs".to_string(),
                    url: url_str.to_string(),
                });
            }
        }
    }

    if sources.is_empty() {
        None
    } else {
        Some(sources)
    }
}

fn parse_torrent_paths(additional: Option<&serde_json::Value>) -> Option<Vec<String>> {
    let arr = additional?.as_object()?.get("torrent_paths")?.as_array()?;

    let paths: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    if paths.is_empty() { None } else { Some(paths) }
}

fn format_filesize(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}B")
    }
}
