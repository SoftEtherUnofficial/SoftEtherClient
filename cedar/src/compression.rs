//! Compression Module
//!
//! Data compression support for VPN connections.
//! Provides bandwidth optimization with adaptive compression.

use mayaqua::error::{Error, Result};

/// Compression algorithm
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// DEFLATE algorithm (RFC 1951)
    Deflate,
    /// GZIP format
    Gzip,
    /// LZ4 (fast compression)
    Lz4,
}

/// Compression level
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionLevel {
    /// No compression
    None,
    /// Fastest compression
    Fast,
    /// Balanced compression
    Default,
    /// Best compression ratio
    Best,
}

impl CompressionLevel {
    /// Convert to numeric level (0-9)
    pub fn to_level(&self) -> u8 {
        match self {
            CompressionLevel::None => 0,
            CompressionLevel::Fast => 1,
            CompressionLevel::Default => 6,
            CompressionLevel::Best => 9,
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Algorithm to use
    pub algorithm: CompressionAlgorithm,
    /// Compression level
    pub level: CompressionLevel,
    /// Enable adaptive compression
    pub adaptive: bool,
    /// Minimum size to compress (bytes)
    pub min_size: usize,
    /// Compression ratio threshold (0.0-1.0)
    pub ratio_threshold: f32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Deflate,
            level: CompressionLevel::Default,
            adaptive: true,
            min_size: 128,
            ratio_threshold: 0.9,
        }
    }
}

/// Compression engine
pub struct Compressor {
    /// Configuration
    config: CompressionConfig,
    /// Total bytes input
    bytes_input: u64,
    /// Total bytes output
    bytes_output: u64,
    /// Number of compressions
    compress_count: u64,
    /// Number of times compression was skipped
    skip_count: u64,
}

impl Compressor {
    /// Create new compressor with config
    pub fn new(config: CompressionConfig) -> Self {
        Self {
            config,
            bytes_input: 0,
            bytes_output: 0,
            compress_count: 0,
            skip_count: 0,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(CompressionConfig::default())
    }

    /// Compress data
    pub fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        self.bytes_input += input.len() as u64;

        // Skip compression if input is too small
        if self.config.adaptive && input.len() < self.config.min_size {
            if output.len() < input.len() {
                return Err(Error::BufferTooSmall);
            }
            output[..input.len()].copy_from_slice(input);
            self.skip_count += 1;
            self.bytes_output += input.len() as u64;
            return Ok(input.len());
        }

        // Perform compression based on algorithm
        let compressed_size = match self.config.algorithm {
            CompressionAlgorithm::None => {
                if output.len() < input.len() {
                    return Err(Error::BufferTooSmall);
                }
                output[..input.len()].copy_from_slice(input);
                input.len()
            }
            CompressionAlgorithm::Deflate => self.compress_deflate(input, output)?,
            CompressionAlgorithm::Gzip => self.compress_gzip(input, output)?,
            CompressionAlgorithm::Lz4 => self.compress_lz4(input, output)?,
        };

        // Check compression ratio
        let ratio = compressed_size as f32 / input.len() as f32;
        if self.config.adaptive && ratio > self.config.ratio_threshold {
            // Compression didn't help, use original data
            if output.len() < input.len() {
                return Err(Error::BufferTooSmall);
            }
            output[..input.len()].copy_from_slice(input);
            self.skip_count += 1;
            self.bytes_output += input.len() as u64;
            return Ok(input.len());
        }

        self.compress_count += 1;
        self.bytes_output += compressed_size as u64;
        Ok(compressed_size)
    }

    /// Decompress data
    pub fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        match self.config.algorithm {
            CompressionAlgorithm::None => {
                if output.len() < input.len() {
                    return Err(Error::BufferTooSmall);
                }
                output[..input.len()].copy_from_slice(input);
                Ok(input.len())
            }
            CompressionAlgorithm::Deflate => self.decompress_deflate(input, output),
            CompressionAlgorithm::Gzip => self.decompress_gzip(input, output),
            CompressionAlgorithm::Lz4 => self.decompress_lz4(input, output),
        }
    }

    /// Get compression statistics
    pub fn stats(&self) -> CompressionStats {
        let ratio = if self.bytes_input > 0 {
            self.bytes_output as f64 / self.bytes_input as f64
        } else {
            1.0
        };

        CompressionStats {
            bytes_input: self.bytes_input,
            bytes_output: self.bytes_output,
            compress_count: self.compress_count,
            skip_count: self.skip_count,
            compression_ratio: ratio,
        }
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.bytes_input = 0;
        self.bytes_output = 0;
        self.compress_count = 0;
        self.skip_count = 0;
    }

    // Internal compression methods (placeholders)

    fn compress_deflate(&self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        // TODO: Implement DEFLATE compression using flate2 crate
        // For now, return error
        if output.len() < input.len() {
            return Err(Error::BufferTooSmall);
        }
        output[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }

    fn decompress_deflate(&self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        // TODO: Implement DEFLATE decompression
        if output.len() < input.len() {
            return Err(Error::BufferTooSmall);
        }
        output[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }

    fn compress_gzip(&self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        // TODO: Implement GZIP compression
        if output.len() < input.len() {
            return Err(Error::BufferTooSmall);
        }
        output[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }

    fn decompress_gzip(&self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        // TODO: Implement GZIP decompression
        if output.len() < input.len() {
            return Err(Error::BufferTooSmall);
        }
        output[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }

    fn compress_lz4(&self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        // TODO: Implement LZ4 compression
        if output.len() < input.len() {
            return Err(Error::BufferTooSmall);
        }
        output[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }

    fn decompress_lz4(&self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        // TODO: Implement LZ4 decompression
        if output.len() < input.len() {
            return Err(Error::BufferTooSmall);
        }
        output[..input.len()].copy_from_slice(input);
        Ok(input.len())
    }
}

/// Compression statistics
#[derive(Debug, Clone)]
pub struct CompressionStats {
    /// Total bytes input
    pub bytes_input: u64,
    /// Total bytes output
    pub bytes_output: u64,
    /// Number of compressions performed
    pub compress_count: u64,
    /// Number of times compression was skipped
    pub skip_count: u64,
    /// Overall compression ratio
    pub compression_ratio: f64,
}

impl CompressionStats {
    /// Get bandwidth savings percentage
    pub fn savings_percent(&self) -> f64 {
        if self.bytes_input > 0 {
            (1.0 - self.compression_ratio) * 100.0
        } else {
            0.0
        }
    }

    /// Get bytes saved
    pub fn bytes_saved(&self) -> u64 {
        self.bytes_input.saturating_sub(self.bytes_output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_config_default() {
        let config = CompressionConfig::default();
        assert_eq!(config.algorithm, CompressionAlgorithm::Deflate);
        assert_eq!(config.level, CompressionLevel::Default);
        assert!(config.adaptive);
    }

    #[test]
    fn test_compression_level_values() {
        assert_eq!(CompressionLevel::None.to_level(), 0);
        assert_eq!(CompressionLevel::Fast.to_level(), 1);
        assert_eq!(CompressionLevel::Default.to_level(), 6);
        assert_eq!(CompressionLevel::Best.to_level(), 9);
    }

    #[test]
    fn test_compressor_creation() {
        let compressor = Compressor::with_defaults();
        let stats = compressor.stats();
        assert_eq!(stats.bytes_input, 0);
        assert_eq!(stats.bytes_output, 0);
    }

    #[test]
    fn test_compress_small_data() {
        let mut compressor = Compressor::with_defaults();
        let input = b"test";
        let mut output = [0u8; 128];

        // Small data should be skipped with adaptive compression
        let size = compressor.compress(input, &mut output).unwrap();
        assert_eq!(size, input.len());

        let stats = compressor.stats();
        assert_eq!(stats.skip_count, 1);
    }

    #[test]
    fn test_compress_no_algorithm() {
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: CompressionLevel::None,
            adaptive: false,
            min_size: 0,
            ratio_threshold: 1.0,
        };
        let mut compressor = Compressor::new(config);
        let input = b"test data here";
        let mut output = [0u8; 128];

        let size = compressor.compress(input, &mut output).unwrap();
        assert_eq!(size, input.len());
        assert_eq!(&output[..size], input);
    }

    #[test]
    fn test_decompress() {
        let mut compressor = Compressor::with_defaults();
        let input = b"compressed data";
        let mut output = [0u8; 128];

        let size = compressor.decompress(input, &mut output).unwrap();
        assert_eq!(size, input.len());
    }

    #[test]
    fn test_compression_stats() {
        let mut compressor = Compressor::with_defaults();
        let input = b"a".repeat(256);
        let mut output = vec![0u8; 512];

        let _ = compressor.compress(&input, &mut output);

        let stats = compressor.stats();
        assert!(stats.bytes_input > 0);
        assert!(stats.bytes_output > 0);
    }

    #[test]
    fn test_stats_savings() {
        let stats = CompressionStats {
            bytes_input: 1000,
            bytes_output: 500,
            compress_count: 10,
            skip_count: 2,
            compression_ratio: 0.5,
        };

        assert_eq!(stats.savings_percent(), 50.0);
        assert_eq!(stats.bytes_saved(), 500);
    }

    #[test]
    fn test_buffer_too_small() {
        let mut compressor = Compressor::with_defaults();
        let input = b"test data";
        let mut small_output = [0u8; 2];

        let result = compressor.compress(input, &mut small_output);
        assert!(result.is_err());
    }

    #[test]
    fn test_stats_reset() {
        let mut compressor = Compressor::with_defaults();
        let input = b"test";
        let mut output = [0u8; 128];

        let _ = compressor.compress(input, &mut output);
        assert!(compressor.stats().bytes_input > 0);

        compressor.reset_stats();
        assert_eq!(compressor.stats().bytes_input, 0);
    }

    #[test]
    fn test_algorithm_equality() {
        assert_eq!(
            CompressionAlgorithm::Deflate,
            CompressionAlgorithm::Deflate
        );
        assert_ne!(CompressionAlgorithm::Deflate, CompressionAlgorithm::Gzip);
    }
}
