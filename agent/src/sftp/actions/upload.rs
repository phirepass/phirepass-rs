use crate::sftp::{FileUpload, SFTPActiveUploads, cleanup_abandoned_uploads, generate_id};
use log::{debug, info, warn};
use phirepass_common::protocol::common::{Frame, FrameError};
use phirepass_common::protocol::node::{NodeFrameData, WebFrameId};
use phirepass_common::protocol::sftp::{SFTPUploadChunk, SFTPUploadStart, SFTPUploadStartResponse};
use phirepass_common::protocol::web::WebFrameData;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

// Upload rate limiting configuration
// Set UPLOAD_CHUNK_ACK_DELAY_MS to add delay before sending chunk acknowledgments
// This controls upload speed: 64KB chunk / delay = max speed
// Examples:
//   0ms = no limit (full speed)
//   10ms = ~6.4 MB/s max
//   50ms = ~1.3 MB/s max
//   100ms = ~640 KB/s max
const UPLOAD_CHUNK_ACK_DELAY_MS: u64 = 0;

pub async fn start_upload(
    tx: &Sender<Frame>,
    sftp_session: &SftpSession,
    upload: &SFTPUploadStart,
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    uploads: &SFTPActiveUploads,
) {
    cleanup_abandoned_uploads(uploads).await;

    let file_path = if upload.remote_path.ends_with('/') {
        format!("{}{}", upload.remote_path, upload.filename)
    } else {
        format!("{}/{}", upload.remote_path, upload.filename)
    };

    info!(
        "starting upload for file {file_path} ({} bytes, {} chunks)",
        upload.total_size, upload.total_chunks
    );

    // Use a temporary path for the upload in progress
    let temp_path = format!("{}.tmp", file_path);

    // Open the file on SFTP with WRITE | CREATE | APPEND
    match sftp_session
        .open_with_flags(
            &temp_path,
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::APPEND,
        )
        .await
    {
        Ok(file) => {
            // Generate unique upload ID
            let upload_id = generate_id();
            let now = std::time::SystemTime::now();

            // Store the file handle and metadata for subsequent chunks
            uploads.insert(
                (cid, upload_id),
                FileUpload {
                    filename: upload.filename.clone(),
                    remote_path: upload.remote_path.clone(),
                    total_chunks: upload.total_chunks,
                    total_size: upload.total_size,
                    sftp_file: file,
                    temp_path: temp_path.clone(),
                    started_at: now,
                    last_updated: now,
                },
            );
            info!(
                "opened file on SFTP for upload: {} (upload_id: {})",
                temp_path, upload_id
            );

            // Send upload start response with upload_id
            let _ = tx
                .send(
                    NodeFrameData::WebFrame {
                        frame: WebFrameData::SFTPUploadStartResponse {
                            sid,
                            msg_id,
                            response: SFTPUploadStartResponse { upload_id },
                        },
                        id: WebFrameId::SessionId(sid),
                    }
                    .into(),
                )
                .await;
        }
        Err(err) => {
            warn!("failed to open file on SFTP: {err}");
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
        }
    }
}

pub async fn upload_file_chunk(
    tx: &Sender<Frame>,
    sftp_session: &SftpSession,
    chunk: &SFTPUploadChunk,
    cid: Uuid,
    sid: u32,
    msg_id: Option<u32>,
    uploads: &SFTPActiveUploads,
) {
    debug!(
        "uploading chunk {} for upload_id {} ({} bytes)",
        chunk.chunk_index,
        chunk.upload_id,
        chunk.data.len()
    );

    let key = (cid, chunk.upload_id);

    // Check if this is the last chunk
    let is_last_chunk = {
        if let Some(file_upload) = uploads.get(&key) {
            chunk.chunk_index + 1 >= file_upload.total_chunks
        } else {
            warn!("upload_id {} not found for cid {}", chunk.upload_id, cid);
            let _ = tx
                .send(
                    NodeFrameData::WebFrame {
                        frame: WebFrameData::Error {
                            kind: FrameError::Generic,
                            message: format!("Upload ID {} not found", chunk.upload_id),
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

    if is_last_chunk {
        // Last chunk: write final chunk, close, and rename
        let mut file_upload = uploads.remove(&key).map(|(_, v)| v);

        if let Some(ref mut upload) = file_upload {
            if let Err(err) = upload.sftp_file.write_all(chunk.data.as_ref()).await {
                warn!("failed to write final chunk to SFTP file: {err}");
                let _ = tx
                    .send(
                        NodeFrameData::WebFrame {
                            frame: WebFrameData::Error {
                                kind: FrameError::Generic,
                                message: format!("Failed to write final chunk: {}", err),
                                msg_id,
                            },
                            id: WebFrameId::SessionId(sid),
                        }
                        .into(),
                    )
                    .await;
                return;
            }

            // Close the file by dropping the whole FileUpload struct
            // (the sftp_file will be closed when dropped)
            debug!("closed file on SFTP after final chunk");

            // Build the final file path
            let file_path = if upload.remote_path.ends_with('/') {
                format!("{}{}", upload.remote_path, upload.filename)
            } else {
                format!("{}/{}", upload.remote_path, upload.filename)
            };

            // Rename from temp to final path
            match sftp_session.rename(&upload.temp_path, &file_path).await {
                Ok(_) => {
                    info!("file upload complete: {}", file_path);

                    // Send acknowledgment for the final chunk
                    let _ = tx
                        .send(
                            NodeFrameData::WebFrame {
                                frame: WebFrameData::SFTPUploadChunkAck {
                                    sid,
                                    upload_id: chunk.upload_id,
                                    chunk_index: chunk.chunk_index,
                                },
                                id: WebFrameId::SessionId(sid),
                            }
                            .into(),
                        )
                        .await;
                }
                Err(err) => {
                    warn!("failed to rename file on SFTP: {}", err);
                    let _ = tx
                        .send(
                            NodeFrameData::WebFrame {
                                frame: WebFrameData::Error {
                                    kind: FrameError::Generic,
                                    message: format!("Failed to rename file: {}", err),
                                    msg_id,
                                },
                                id: WebFrameId::SessionId(sid),
                            }
                            .into(),
                        )
                        .await;
                }
            }
        } else {
            warn!(
                "file upload not found for final chunk upload_id {}",
                chunk.upload_id
            );
            let _ = tx
                .send(
                    NodeFrameData::WebFrame {
                        frame: WebFrameData::Error {
                            kind: FrameError::Generic,
                            message: "File upload not found for final chunk".to_string(),
                            msg_id,
                        },
                        id: WebFrameId::SessionId(sid),
                    }
                    .into(),
                )
                .await;
        }
    } else {
        // Intermediate chunk: write and continue
        if let Some(mut file_upload) = uploads.get_mut(&key) {
            if let Err(err) = file_upload.sftp_file.write_all(chunk.data.as_ref()).await {
                warn!(
                    "failed to write chunk {} to SFTP file: {err}",
                    chunk.chunk_index
                );
                if let Some((_, file_upload)) = uploads.remove(&key) {
                    debug!(
                        "closed sftp file for upload due to write error: {}",
                        file_upload.filename
                    );
                    // FileUpload is dropped here, closing the sftp_file
                }
                let _ = tx
                    .send(
                        NodeFrameData::WebFrame {
                            frame: WebFrameData::Error {
                                kind: FrameError::Generic,
                                message: format!("Failed to write chunk: {}", err),
                                msg_id,
                            },
                            id: WebFrameId::SessionId(sid),
                        }
                        .into(),
                    )
                    .await;
                return;
            }
            // Update last_updated timestamp after successful write
            file_upload.last_updated = std::time::SystemTime::now();
            debug!(
                "appended chunk {} to SFTP file for upload_id {}",
                chunk.chunk_index, chunk.upload_id
            );

            // Apply rate limiting if configured
            if UPLOAD_CHUNK_ACK_DELAY_MS != 0 {
                sleep(Duration::from_millis(UPLOAD_CHUNK_ACK_DELAY_MS)).await;
            }

            // Send acknowledgment for this chunk
            let _ = tx
                .send(
                    NodeFrameData::WebFrame {
                        frame: WebFrameData::SFTPUploadChunkAck {
                            sid,
                            upload_id: chunk.upload_id,
                            chunk_index: chunk.chunk_index,
                        },
                        id: WebFrameId::SessionId(sid),
                    }
                    .into(),
                )
                .await;
        } else {
            warn!(
                "upload_id {} not found for chunk {}",
                chunk.upload_id, chunk.chunk_index
            );
            let _ = tx
                .send(
                    NodeFrameData::WebFrame {
                        frame: WebFrameData::Error {
                            kind: FrameError::Generic,
                            message: format!("Upload ID {} not found", chunk.upload_id),
                            msg_id,
                        },
                        id: WebFrameId::SessionId(sid),
                    }
                    .into(),
                )
                .await;
        }
    }
}
