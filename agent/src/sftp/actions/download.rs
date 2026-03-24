use crate::sftp::{
    CHUNK_SIZE, FileDownload, SFTPActiveDownloads, cleanup_abandoned_downloads, generate_id,
};
use bytes::Bytes;
use log::{debug, info, warn};
use phirepass_common::protocol::common::{Frame, FrameError};
use phirepass_common::protocol::node::{NodeFrameData, WebFrameId};
use phirepass_common::protocol::sftp::{
    SFTPDownloadChunk, SFTPDownloadStart, SFTPDownloadStartResponse,
};
use phirepass_common::protocol::web::WebFrameData;
use russh_sftp::client::SftpSession;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

// Download rate limiting configuration
// Set DOWNLOAD_CHUNK_DELAY_MS to add delay before sending each chunk
// This controls download speed: 64KB chunk / delay = max speed
// Examples:
//   0ms = no limit (full speed)
//   10ms = ~6.4 MB/s max
//   50ms = ~1.3 MB/s max
//   100ms = ~640 KB/s max
const DOWNLOAD_CHUNK_DELAY_MS: u64 = 0;

pub async fn start_download(
    tx: &Sender<Frame>,
    sftp_session: &SftpSession,
    download: &SFTPDownloadStart,
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    downloads: &SFTPActiveDownloads,
) {
    cleanup_abandoned_downloads(downloads).await;

    let file_path = if download.path.ends_with('/') {
        format!("{}{}", download.path, download.filename)
    } else {
        format!("{}/{}", download.path, download.filename)
    };

    info!("starting download: {file_path}");

    // Get file metadata to determine size
    let metadata = match sftp_session.metadata(&file_path).await {
        Ok(meta) => meta,
        Err(err) => {
            warn!("failed to get file metadata for {file_path}: {err}");
            let _ = tx
                .send(
                    NodeFrameData::WebFrame {
                        frame: WebFrameData::Error {
                            kind: FrameError::Generic,
                            message: format!("Failed to get file metadata: {}", err),
                            msg_id,
                        },
                        id: WebFrameId::SessionId(sid),
                    }
                    .into(),
                )
                .await;
            return;
        }
    };

    let total_size = metadata.size.unwrap_or(0);
    let total_chunks = ((total_size as f64) / (CHUNK_SIZE as f64)).ceil() as u32;

    debug!("file size: {total_size} bytes, will send {total_chunks} chunks");

    // Open the file
    let file = match sftp_session.open(&file_path).await {
        Ok(f) => f,
        Err(err) => {
            warn!("failed to open file {file_path}: {err}");
            let _ = tx
                .send(
                    NodeFrameData::WebFrame {
                        frame: WebFrameData::Error {
                            kind: FrameError::Generic,
                            message: format!("Failed to open file: {}", err),
                            msg_id,
                        },
                        id: WebFrameId::SessionId(sid),
                    }
                    .into(),
                )
                .await;
            return;
        }
    };

    // Generate unique download ID
    let download_id = generate_id();
    let now = SystemTime::now();

    // Store the file handle and metadata for subsequent chunks
    downloads.insert(
        (cid, download_id),
        FileDownload {
            filename: download.filename.clone(),
            total_size,
            total_chunks,
            sftp_file: file,
            started_at: now,
            last_updated: now,
        },
    );
    info!(
        "opened file on SFTP for download: {} (download_id: {})",
        file_path, download_id
    );

    // Send download start response with download_id
    let _ = tx
        .send(
            NodeFrameData::WebFrame {
                frame: WebFrameData::SFTPDownloadStartResponse {
                    sid,
                    msg_id,
                    response: SFTPDownloadStartResponse {
                        download_id,
                        total_size,
                        total_chunks,
                    },
                },
                id: WebFrameId::SessionId(sid),
            }
            .into(),
        )
        .await;
}

pub async fn download_file_chunk(
    tx: &Sender<Frame>,
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    download_id: u32,
    chunk_index: u32,
    downloads: &SFTPActiveDownloads,
) {
    let key = (cid, download_id);

    let mut should_remove = false;
    match downloads.get_mut(&key) {
        Some(mut download) => {
            let mut buffer = vec![0u8; CHUNK_SIZE];

            // Seek to the correct position for this chunk
            let chunk_position = (chunk_index as u64) * (CHUNK_SIZE as u64);
            if let Err(err) = download
                .sftp_file
                .seek(std::io::SeekFrom::Start(chunk_position))
                .await
            {
                warn!(
                    "error seeking to position {} for download_id {download_id} at chunk {chunk_index}: {err}",
                    chunk_position
                );
                let _ = tx
                    .send(
                        NodeFrameData::WebFrame {
                            frame: WebFrameData::Error {
                                kind: FrameError::Generic,
                                message: format!("Error seeking file: {}", err),
                                msg_id,
                            },
                            id: WebFrameId::SessionId(sid),
                        }
                        .into(),
                    )
                    .await;
                should_remove = true;
            } else {
                match download.sftp_file.read(&mut buffer).await {
                    Ok(0) => {
                        // EOF reached
                        info!(
                            "file download complete: {} (download_id: {}), sent {} chunks",
                            download.filename, download_id, chunk_index
                        );
                        // Mark for removal
                        should_remove = true;
                    }
                    Ok(bytes_read) => {
                        let chunk_data = Bytes::copy_from_slice(&buffer[..bytes_read]);
                        let chunk = SFTPDownloadChunk {
                            download_id,
                            chunk_index,
                            chunk_size: bytes_read as u32,
                            data: chunk_data,
                        };

                        // Update last_updated timestamp
                        download.last_updated = SystemTime::now();

                        debug!(
                            "sending chunk {}/{} ({} bytes) for download_id {}",
                            chunk_index + 1,
                            download.total_chunks,
                            bytes_read,
                            download_id
                        );

                        // Apply rate limiting if configured
                        if DOWNLOAD_CHUNK_DELAY_MS != 0 {
                            sleep(Duration::from_millis(DOWNLOAD_CHUNK_DELAY_MS)).await;
                        }

                        if let Err(err) = tx
                            .send(
                                NodeFrameData::WebFrame {
                                    frame: WebFrameData::SFTPDownloadChunk { sid, msg_id, chunk },
                                    id: WebFrameId::SessionId(sid),
                                }
                                .into(),
                            )
                            .await
                        {
                            warn!(
                                "failed to send chunk {chunk_index} for download_id {download_id}: {err}"
                            );
                        }
                    }
                    Err(err) => {
                        warn!(
                            "error reading file for download_id {download_id} at chunk {chunk_index}: {err}"
                        );
                        let _ = tx
                            .send(
                                NodeFrameData::WebFrame {
                                    frame: WebFrameData::Error {
                                        kind: FrameError::Generic,
                                        message: format!("Error reading file: {}", err),
                                        msg_id,
                                    },
                                    id: WebFrameId::SessionId(sid),
                                }
                                .into(),
                            )
                            .await;
                        should_remove = true;
                    }
                }
            }
        }
        None => {
            warn!("download not found: {:?}", key);
            let _ = tx
                .send(
                    NodeFrameData::WebFrame {
                        frame: WebFrameData::Error {
                            kind: FrameError::Generic,
                            message: "Download not found or expired".to_string(),
                            msg_id,
                        },
                        id: WebFrameId::SessionId(sid),
                    }
                    .into(),
                )
                .await;
        }
    }

    // Remove the download entry if EOF or error was encountered
    if should_remove && let Some((_, file_download)) = downloads.remove(&key) {
        debug!("closed sftp file for download: {}", file_download.filename);
        // FileDownload is dropped here, closing the sftp_file
    }
}
