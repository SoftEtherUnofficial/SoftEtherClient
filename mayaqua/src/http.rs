//! HTTP utilities for SoftEther VPN protocol communication

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};

/// HTTP request structure
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP response structure
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Create a new HTTP request
    pub fn new(method: String, path: String) -> Self {
        Self {
            method,
            path,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Create a new HTTP POST request for SoftEther VPN protocol
    /// Wraps binary PACK data in proper HTTP headers
    /// 
    /// Header order matches OpenSSL's HttpClientSend() exactly:
    /// 1. Date, 2. Host, 3. Keep-Alive, 4. Connection, 5. Content-Type, 6. Content-Length
    pub fn new_vpn_post(hostname: &str, port: u16, pack_data: Vec<u8>) -> Self {
        let mut request = Self::new("POST".to_string(), "/vpnsvc/vpn.cgi".to_string());
        
        // Add headers in exact order as OpenSSL HttpClientSend()
        // See: SoftEtherVPN_Stable/src/Mayaqua/Network.c:22897
        
        // 1. Date header (RFC 2822 format)
        request.add_header("Date".to_string(), get_http_date());
        
        // 2. Host header (WITHOUT port - OpenSSL doesn't include it)
        request.add_header("Host".to_string(), hostname.to_string());
        
        // 3. Keep-Alive header
        request.add_header("Keep-Alive".to_string(), "timeout=60, max=1000".to_string());
        
        // 4. Connection header
        request.add_header("Connection".to_string(), "Keep-Alive".to_string());
        
        // 5. Content-Type header (binary PACK data)
        request.add_header("Content-Type".to_string(), "application/octet-stream".to_string());
        
        // Suppress unused parameter warning
        let _ = port;
        
        // Set binary PACK body (Content-Length added automatically by set_body)
        request.set_body(pack_data);
        
        request
    }

    /// Add a header to the request
    pub fn add_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    /// Set the request body
    pub fn set_body(&mut self, body: Vec<u8>) {
        let body_len = body.len();
        self.body = body;
        self.add_header("Content-Length".to_string(), body_len.to_string());
    }

    /// Convert the request to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut request = format!("{} {} HTTP/1.1\r\n", self.method, self.path);

        // Add headers
        for (name, value) in &self.headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }

        // End headers
        request.push_str("\r\n");

        // Convert to bytes and append body
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(&self.body);

        bytes
    }
}

impl HttpResponse {
    /// Parse an HTTP response from a stream
    pub fn from_stream<R: Read>(stream: &mut R) -> Result<Self> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        // Read status line
        reader
            .read_line(&mut line)
            .map_err(|e| Error::Network(format!("Failed to read status line: {e}")))?;

        let status_parts: Vec<&str> = line.split_whitespace().collect();
        if status_parts.len() < 2 {
            return Err(Error::Network("Invalid HTTP status line".to_string()));
        }

        let status_code = status_parts[1]
            .parse::<u16>()
            .map_err(|e| Error::Network(format!("Invalid status code: {e}")))?;

        // Read headers
        let mut headers = HashMap::new();
        let mut content_length = 0;

        loop {
            line.clear();
            reader
                .read_line(&mut line)
                .map_err(|e| Error::Network(format!("Failed to read header: {e}")))?;

            let line = line.trim();
            if line.is_empty() {
                break; // End of headers
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();

                if name == "content-length" {
                    content_length = value
                        .parse::<usize>()
                        .map_err(|e| Error::Network(format!("Invalid content-length: {e}")))?;
                }

                headers.insert(name, value);
            }
        }

        // Read body
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader
                .read_exact(&mut body)
                .map_err(|e| Error::Network(format!("Failed to read body: {e}")))?;
        }

        Ok(Self {
            status_code,
            headers,
            body,
        })
    }

    /// Get a header value
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Check if the response is successful (2xx status code)
    pub fn is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }
}

/// Get current time formatted as HTTP date string (RFC 2822)
/// Example: "Thu, 10 Oct 2025 14:00:00 GMT"
fn get_http_date() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    
    let timestamp = duration.as_secs();
    
    // Day names
    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    // Month names
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    
    // Calculate date components
    let total_days = timestamp / 86400;
    let day_of_week = ((total_days + 4) % 7) as usize; // Unix epoch was Thursday
    
    let seconds_today = timestamp % 86400;
    let hours = seconds_today / 3600;
    let minutes = (seconds_today % 3600) / 60;
    let seconds = seconds_today % 60;
    
    // Approximate year/month/day (good enough for HTTP header)
    let years_since_epoch = total_days / 365;
    let year = 1970 + years_since_epoch;
    let remaining_days = total_days % 365;
    let month = (remaining_days / 30).min(11) as usize;
    let day = (remaining_days % 30) + 1;
    
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        days[day_of_week],
        day,
        months[month],
        year,
        hours,
        minutes,
        seconds
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_http_request_creation() {
        let mut request = HttpRequest::new("GET".to_string(), "/test".to_string());
        request.add_header("Host".to_string(), "example.com".to_string());
        request.set_body(b"test body".to_vec());

        let bytes = request.to_bytes();
        let request_str = String::from_utf8_lossy(&bytes);

        assert!(request_str.contains("GET /test HTTP/1.1"));
        assert!(request_str.contains("Host: example.com"));
        assert!(request_str.contains("Content-Length: 9"));
        assert!(request_str.ends_with("test body"));
    }

    #[test]
    fn test_http_response_parsing() -> Result<()> {
        let response_data =
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nHello World";
        let mut cursor = Cursor::new(response_data);

        let response = HttpResponse::from_stream(&mut cursor)?;

        assert_eq!(response.status_code, 200);
        assert_eq!(
            response.get_header("content-length"),
            Some(&"11".to_string())
        );
        assert_eq!(
            response.get_header("content-type"),
            Some(&"text/plain".to_string())
        );
        assert_eq!(response.body, b"Hello World");
        assert!(response.is_success());

        Ok(())
    }

    #[test]
    fn test_http_response_no_body() -> Result<()> {
        let response_data = b"HTTP/1.1 204 No Content\r\n\r\n";
        let mut cursor = Cursor::new(response_data);

        let response = HttpResponse::from_stream(&mut cursor)?;

        assert_eq!(response.status_code, 204);
        assert!(response.body.is_empty());
        assert!(response.is_success());

        Ok(())
    }
}
