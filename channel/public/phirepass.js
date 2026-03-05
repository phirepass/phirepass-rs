import init, {
    ErrorType,
    Channel as PhirepassChannel,
} from "/pkg/debug/phirepass-channel.js";
import { SFTPBrowser } from "./sftp.js";

async function setup() {
    await init(); // Load WebAssembly module
}

const statusEl = document.getElementById("status");
const logEl = document.getElementById("log");
const connectBtn = document.getElementById("connect");
const terminalHost = document.getElementById("terminal");
const nodesSshEl = document.getElementById("nodes-ssh");
const nodesSftpEl = document.getElementById("nodes-sftp");
const refreshBtnSsh = document.getElementById("refresh-nodes-ssh");
const refreshBtnSftp = document.getElementById("refresh-nodes-sftp");
const fullscreenBtn = document.getElementById("fullscreen");
const tabNavigation = document.getElementById("tab-navigation");
const tabButtons = document.querySelectorAll(".tab-button");

const wsScheme = window.location.protocol === "https:" ? "wss" : "ws";

const wsEndpoint = `wss://api.phirepass.com`;
const httpEndpoint = `https://api.phirepass.com`;

let term, fitAddon;
let socket; // SSH socket
let sftpSocket; // Separate SFTP socket
let nodes = [];
let nodesSftp = [];
let selected_node_id = null; // SSH selected node
let selected_node_id_sftp = null; // SFTP selected node
let session_id = null;
let isIntentionallyClosed = false;
let isSshConnected = false;
let sftpBrowser = null;
let currentTab = "ssh"; // Track current active tab

let credentialMode = null; // "username" | "password" | "username-only"
let usernameBuffer = "";
let passwordBuffer = "";
let session_username = "";

const log = (text) => {
    const line = document.createElement("div");
    line.className = "log-line";
    line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
};

const setStatus = (text, variant = "info") => {
    statusEl.textContent = text;
    const colors = {
        info: "rgba(59, 130, 246, 0.12)",
        ok: "rgba(34, 197, 94, 0.18)",
        warn: "rgba(234, 179, 8, 0.16)",
        error: "rgba(239, 68, 68, 0.18)",
    };
    statusEl.style.background = colors[variant] || colors.info;
};

const formatNumber = (value, digits = 1) =>
    Number.isFinite(value) ? value.toFixed(digits) : "n/a";

const formatBytes = (bytes) => {
    if (!Number.isFinite(bytes)) return "n/a";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let size = bytes;
    let unit = units.shift();
    while (units.length && size >= 1024) {
        size /= 1024;
        unit = units.shift();
    }
    return `${size.toFixed(1)} ${unit}`;
};

const switchTab = (tabName) => {
    currentTab = tabName;

    // Update button states
    tabButtons.forEach(btn => {
        btn.classList.toggle("active", btn.dataset.tab === tabName);
    });

    // Update content visibility
    const sshContent = document.getElementById("tab-content-ssh");
    const sftpContent = document.getElementById("tab-content-sftp");

    if (tabName === "ssh") {
        sshContent.classList.add("active");
        sftpContent.classList.remove("active");
        if (term) fitAddon.fit();
    } else if (tabName === "sftp") {
        sshContent.classList.remove("active");
        sftpContent.classList.add("active");
    }
};

const fetchNodes = async () => {
    try {
        // Fetch nodes for both SSH and SFTP tabs
        const res = await fetch(`${httpEndpoint}/api/nodes`);
        if (!res.ok) {
            log(`Failed to fetch nodes`);
            return;
        }
        const nodeList = await res.json();

        // Use same node list for both SSH and SFTP
        nodes = nodeList;
        nodesSftp = nodeList;

        renderNodes(nodes, nodesSshEl, 'ssh');
        renderNodes(nodesSftp, nodesSftpEl, 'sftp');
    } catch (err) {
        log(`Failed to fetch nodes: ${err.message}`);
    }
};

const renderNodes = (list, containerEl, tabType) => {
    containerEl.innerHTML = "";
    if (!list.length) {
        const empty = document.createElement("div");
        empty.style.color = "#94a3b8";
        empty.textContent = "No nodes connected.";
        containerEl.appendChild(empty);
        return;
    }

    list.forEach((node) => {
        const card = document.createElement("div");
        card.className = "node-card";
        card.dataset.nodeId = node.id;

        const name = document.createElement("div");
        name.className = "node-name";
        name.textContent = node.id;
        card.appendChild(name);

        const meta = document.createElement("div");
        meta.className = "node-meta";
        const stats = node.stats || {};
        meta.innerHTML = [
            `ip: ${node.ip}`,
            `uptime: ${formatNumber(node.connected_for_secs / 60, 1)} min`,
            `last hb: ${formatNumber(node.since_last_heartbeat_secs, 1)}s`,
            `cpu: ${formatNumber(stats.host_cpu, 1)}%`,
            `host_mem: ${formatBytes(stats.host_mem_used_bytes)} / ${formatBytes(
                stats.host_mem_total_bytes
            )}`,
        ]
            .map((line) => `<div>${line}</div>`)
            .join("");
        card.appendChild(meta);

        card.addEventListener("click", () => {
            if (tabType === "ssh") {
                // Check if there's an active SSH connection
                if (socket && socket.is_connected()) {
                    const confirmed = confirm(
                        `You are currently connected via SSH. Do you want to disconnect and switch to ${node.id}?`
                    );
                    if (!confirmed) {
                        return;
                    }
                }

                selected_node_id = node.id;
                Array.from(nodesSshEl.children).forEach((el) =>
                    el.classList.toggle("selected", el.dataset.nodeId === node.id)
                );
                log(`Selected SSH node ${node.id}`);

                socket = connect();
            } else if (tabType === "sftp") {
                // Check if there's an active SFTP connection
                if (sftpSocket && sftpSocket.is_connected()) {
                    const confirmed = confirm(
                        `You are currently connected via SFTP. Do you want to disconnect and switch to ${node.id}?`
                    );
                    if (!confirmed) {
                        return;
                    }
                }

                selected_node_id_sftp = node.id;
                Array.from(nodesSftpEl.children).forEach((el) =>
                    el.classList.toggle("selected", el.dataset.nodeId === node.id)
                );
                log(`Selected SFTP node ${node.id}`);

                // Create SFTP socket connection
                if (!sftpBrowser) {
                    sftpBrowser = new SFTPBrowser(wsEndpoint);
                }
                sftpSocket = connectSFTP();
            }
        });

        containerEl.appendChild(card);
    });
};

const cleanup = () => {
    // Close SSH socket
    if (socket) {
        isIntentionallyClosed = true;
        socket.disconnect();
        socket = null;
    }

    // Close SFTP socket
    if (sftpSocket) {
        sftpSocket.disconnect();
        sftpSocket = null;
    }

    if (sftpBrowser) {
        sftpBrowser.disconnect();
    }

    resetCredentialCapture();
    session_username = "";
    session_id = null;
    isSshConnected = false;
    if (fitAddon) fitAddon.fit();
};

const resetCredentialCapture = () => {
    credentialMode = null;
    usernameBuffer = "";
    passwordBuffer = "";
};

const promptForUsername = () => {
    resetCredentialCapture();
    session_username = "";
    term.reset();
    term.write("Enter username: ");
    credentialMode = "username";
    setStatus("Username required", "warn");
};

const promptForPassword = (shouldReset = false) => {
    if (shouldReset) {
        term.reset();
    } else {
        term.writeln("");
    }
    passwordBuffer = "";
    credentialMode = "password";
    term.write("Enter password: ");
    setStatus("Enter password", "warn");
};

const submitUsername = (requirePassword = true) => {
    const username = usernameBuffer.trim();
    if (!username.length) {
        log("Username is required to start SSH session");
        term.writeln("");
        term.write("Enter username: ");
        usernameBuffer = "";
        return;
    }

    session_username = username;

    if (requirePassword) {
        // Requires both username and password
        promptForPassword(true);
    } else {
        // Only username required, send with empty password
        resetCredentialCapture();
        setStatus("Authenticating...", "info");
        log(`Attempting SSH connection with username only...`);

        if (socket_healthy()) {
            socket.open_ssh_tunnel(selected_node_id, session_username, "");
        }
    }
};

const cancelCredentialEntry = () => {
    resetCredentialCapture();
    log("Credential entry cancelled");
    setStatus("Idle", "warn");
    cleanup();
};

const handleUsernameKeystroke = (data, requirePassword = true) => {
    if (data === "\r" || data === "\n") {
        term.write("\r\n");
        submitUsername(requirePassword);
        return;
    }

    if (data === "\u0003") {
        term.write("^C\r\n");
        cancelCredentialEntry();
        return;
    }

    if (data === "\u007f") {
        if (usernameBuffer.length) {
            usernameBuffer = usernameBuffer.slice(0, -1);
            term.write("\b \b");
        }
        return;
    }

    if (data >= " " && data <= "~") {
        usernameBuffer += data;
        term.write(data);
    }
};

const submitPassword = () => {
    const password = passwordBuffer;
    resetCredentialCapture();

    if (!password.length) {
        log("Password is required to start SSH session");
        promptForPassword();
        return;
    }

    if (!session_username) {
        log("Username is required before submitting password");
        promptForUsername();
        return;
    }

    setStatus("Authenticating...", "info");
    log(
        `Credentials submitted for user, attempting SSH connection...`
    );

    if (socket_healthy()) {
        socket.open_ssh_tunnel(selected_node_id, session_username, password);
    }
};

const handlePasswordKeystroke = (data) => {
    // Enter submits the captured password.
    if (data === "\r" || data === "\n") {
        term.write("\r\n");
        submitPassword();
        return;
    }

    // Ctrl+C cancels capture and disconnects.
    if (data === "\u0003") {
        term.write("^C\r\n");
        cancelCredentialEntry();
        return;
    }

    // Handle backspace - no visual feedback to hide password length.
    if (data === "\u007f") {
        if (passwordBuffer.length) {
            passwordBuffer = passwordBuffer.slice(0, -1);
        }
        return;
    }

    // Accept only printable characters - silently capture without visual feedback.
    if (data >= " " && data <= "~") {
        passwordBuffer += data;
    }
};

function socket_healthy() {
    if (socket) {
        if (socket.is_connected()) {
            return true;
        }
    }

    return false;
}

function sftp_socket_healthy() {
    if (sftpSocket) {
        if (sftpSocket.is_connected()) {
            return true;
        }
    }

    return false;
}

function connectSFTP() {
    if (!selected_node_id_sftp) {
        log("Select a node before connecting to SFTP");
        return;
    }

    // Close any existing SFTP connection
    if (sftpSocket) {
        sftpSocket.disconnect();
    }

    setStatus("Connecting to SFTP...");
    log("Establishing SFTP connection...");

    const channel = new PhirepassChannel(`${wsEndpoint}/api/web/ws`, selected_node_id_sftp);

    channel.on_connection_open(() => {
        channel.start_heartbeat();
        // Don't open tunnel here - wait for credentials
        log("SFTP WebSocket connected");
        setStatus("Awaiting credentials...", "info");

        // Show credentials modal immediately
        if (!sftpBrowser) {
            sftpBrowser = new SFTPBrowser(wsEndpoint);
        }
        sftpBrowser.socket = channel;
        sftpBrowser.selectedNode = selected_node_id_sftp;
        sftpBrowser.container.style.display = "flex";
        sftpBrowser.showCredentialsModal();
    });

    channel.on_connection_message((_event) => {
        // console.log(">> on connection message", event);
    });

    channel.on_connection_error((event) => {
        setStatus("SFTP Error", "error");
        log(`SFTP Socket error: ${event.message ?? "unknown error"}`);
        sftpSocket = null;
    });

    channel.on_connection_close((event) => {
        if (currentTab === "sftp") {
            setStatus("SFTP Disconnected", "warn");
            const reason = event.reason || `code ${event.code}`;
            log(`SFTP Socket closed (${reason})`);
            if (sftpBrowser) {
                sftpBrowser.disconnect();
            }
        }
        sftpSocket = null;
    });

    channel.on_protocol_message((frame) => {
        switch (frame.data.web.type) {
            case "SFTPListItems":
                if (sftpBrowser && currentTab === "sftp") {
                    // frame.data.web.dir is a SFTPListItem object with an 'items' array
                    // Process each item in the directory
                    const dirItem = frame.data.web.dir;
                    if (dirItem && dirItem.items && Array.isArray(dirItem.items)) {
                        dirItem.items.forEach(item => {
                            // Convert item to expected format
                            const formattedItem = {
                                name: item.name,
                                is_dir: item.kind === "Folder" || item.kind === 1,
                                size: item.attributes ? item.attributes.size : 0
                            };
                            sftpBrowser.handleListItems(
                                frame.data.web.msg_id,
                                formattedItem,
                                frame.data.web.dir.path
                            );
                        });
                        // Always call handleListComplete after processing all items (even if empty)
                        sftpBrowser.handleListComplete(frame.data.web.msg_id, frame.data.web.dir.path);
                    }
                }
                break;
            case "SFTPDownloadStartResponse":
                if (sftpBrowser && currentTab === "sftp") {
                    try {
                        const response = frame.data.web.response;
                        if (response && response.download_id !== undefined) {
                            sftpBrowser.handleDownloadStartResponse(frame.data.web.msg_id, response.download_id, response.total_size, response.total_chunks);
                        }
                    } catch (err) {
                        console.error("Error handling download start response:", err);
                    }
                }
                break;
            case "SFTPDownloadChunk":
                if (sftpBrowser && currentTab === "sftp") {
                    try {
                        const chunk = frame.data.web.chunk;
                        if (chunk) {
                            sftpBrowser.handleDownloadChunk(frame.data.web.msg_id, chunk);
                        }
                    } catch (err) {
                        console.error("Error handling download chunk:", err);
                    }
                }
                break;
            case "SFTPUploadStartResponse":
                if (sftpBrowser && currentTab === "sftp") {
                    const response = frame.data.web.response;
                    if (response && response.upload_id !== undefined) {
                        sftpBrowser.handleUploadStartResponse(frame.data.web.msg_id, response.upload_id);
                    }
                }
                break;
            case "SFTPUploadChunkAck":
                if (sftpBrowser && currentTab === "sftp") {
                    const upload_id = frame.data.web.upload_id;
                    const chunk_index = frame.data.web.chunk_index;
                    if (upload_id !== undefined && chunk_index !== undefined) {
                        sftpBrowser.handleUploadChunkAck(upload_id, chunk_index);
                    }
                }
                break;
            case "TunnelOpened":
                if (currentTab === "sftp") {
                    if (!sftpBrowser) {
                        sftpBrowser = new SFTPBrowser(wsEndpoint);
                    }
                    sftpBrowser.socket = channel;
                    sftpBrowser.selectedNode = selected_node_id_sftp;
                    sftpBrowser.handleTunnelOpened(frame.data.web.sid);
                    log("SFTP tunnel established");
                    setStatus("SFTP Connected", "ok");
                    // Enable upload button
                    const sftpUploadBtn = document.getElementById("sftp-upload");
                    if (sftpUploadBtn) sftpUploadBtn.disabled = false;
                }
                break;
            case "TunnelClosed":
                if (currentTab === "sftp") {
                    log(`SFTP Tunnel closed - Session ID: ${frame.data.web.sid}`);
                    sftpBrowser.disconnect();
                    setStatus("SFTP Disconnected", "warn");
                    // Disable upload button
                    const sftpUploadBtn = document.getElementById("sftp-upload");
                    if (sftpUploadBtn) sftpUploadBtn.disabled = true;
                }
                break;
            case "Error":
                const isSftpContext = currentTab === "sftp";
                if (!isSftpContext) break;

                switch (frame.data.web.kind) {
                    case ErrorType.RequiresPassword:
                        if (sftpBrowser) {
                            sftpBrowser.showCredentialsModal();
                            setStatus("SFTP Password required", "warn");
                            log("SFTP password is required.");
                        }
                        break;
                    case ErrorType.Generic:
                    default:
                        const message = frame?.data?.web?.message || "An unknown error occurred.";
                        if (sftpBrowser) {
                            sftpBrowser.handleListingError(frame.data.web.msg_id, message);
                            setStatus("SFTP Error", "error");
                        }
                }
                break;
            default:
                const msg = frame?.data?.web?.message || "An unknown error occurred.";
                if (currentTab === "sftp" && sftpBrowser) {
                    sftpBrowser.handleError(null, msg);
                }
        }
    });

    channel.connect();

    return channel;
}

function connect() {
    if (!selected_node_id) {
        log("Select a node before connecting");
        return;
    }

    // Close any active channel before opening a new one.
    cleanup();

    term.reset();
    fitAddon.fit();
    setStatus("Connecting...");

    const channel = new PhirepassChannel(`${wsEndpoint}/api/web/ws`, selected_node_id);

    channel.on_connection_open(() => {
        channel.start_heartbeat();
        channel.open_ssh_tunnel(selected_node_id);
        log("WebSocket connected");
        setStatus("Connecting to node...", "info");
    });

    channel.on_connection_message((_event) => {
        // console.log(">> on connection message", event);
    });

    channel.on_connection_error((event) => {
        setStatus("Error", "error");
        log(`Socket error: ${event.message ?? "unknown error"}`);
    });

    channel.on_connection_close((event) => {
        if (!isIntentionallyClosed) {
            setStatus("Disconnected", "warn");
            const reason = event.reason || `code ${event.code}`;
            log(`Socket closed (${reason})`);
            term.reset();
            cleanup();
        } else {
            log("WebSocket connection closed");
        }
        isIntentionallyClosed = false;
    });

    channel.on_protocol_message((frame) => {
        switch (frame.data.web.type) {
            case "TunnelData":
                if (!isSshConnected) {
                    isSshConnected = true;
                    const target = selected_node_id || frame?.data?.web?.node_id || "selected node";
                    log(`SSH login successful on ${target}`);
                    setStatus("Connected", "ok");
                    term.reset();
                }
                term.write(new Uint8Array(frame.data.web.data));
                break;
            case "TunnelOpened":
                // log(`SSH Tunnel opened - Session ID: ${frame.data.web.sid}`);
                // setStatus("Tunnel established", "info");
                session_id = frame.data.web.sid;
                if (socket_healthy()) {
                    channel.send_ssh_terminal_resize(selected_node_id, session_id, term.cols, term.rows);
                }
                break;
            case "TunnelClosed":
                log(`SSH Tunnel closed - Session ID: ${frame.data.web.sid}`);
                setStatus("Tunnel closed", "warn");
                term.reset();
                cleanup();
                break;
            case "Error":
                switch (frame.data.web.kind) {
                    case ErrorType.RequiresUsername:
                        // Only username required, password should be empty
                        term.reset();
                        setStatus("Username required", "warn");
                        log("SSH username is required.");
                        resetCredentialCapture();
                        session_username = "";
                        term.write("Enter username: ");
                        credentialMode = "username-only";
                        break;
                    case ErrorType.RequiresPassword:
                        // Only password required, keep the username
                        term.reset();
                        setStatus("Password required", "warn");
                        log("SSH password is required.");
                        passwordBuffer = "";
                        credentialMode = "password";
                        term.write("Enter password: ");
                        break;
                    case ErrorType.Generic:
                    default:
                        term.reset();
                        const message = frame?.data?.web?.message || "An unknown error occurred.";
                        setStatus("Error", "error");
                        log(message);

                        // If error comes before any tunnel data, reset everything
                        if (!isSshConnected) {
                            session_username = "";
                            resetCredentialCapture();
                            cleanup();
                        } else {
                            // Already connected, just prompt for username
                            session_username = "";
                            isSshConnected = false;
                            promptForUsername();
                        }
                }
                break;
            default:
                term.reset();
                const message = frame?.data?.web?.message || "An unknown error occurred.";
                setStatus("Auth failed", "error");
                log(message);
                session_username = "";
                isSshConnected = false;
                promptForUsername();
        }
    });

    channel.connect();

    return channel;
}

function setup_terminal() {
    const term = new Terminal({
        convertEol: true,
        cursorBlink: true,
        fontFamily:
            '"Berkeley Mono", "Fira Code", "SFMono-Regular", Menlo, monospace',
        fontSize: 14,
        allowProposedApi: true, // needed for bracketed paste
        rightClickSelectsWord: false,
        bellStyle: "sound",
        disableStdin: false,
        windowsMode: false,
        logLevel: "info",
        theme: {
            background: "#0b1021",
            foreground: "#e2e8f0",
            cursor: "#67e8f9",
        },
    });
    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalHost);
    fitAddon.fit();
    term.focus();
    term.pasteMode = "bracketed"; // enable bracketed paste sequences
    return [term, fitAddon];
}

document.addEventListener("DOMContentLoaded", () => {
    connectBtn.addEventListener("click", connect);
    refreshBtnSsh.addEventListener("click", fetchNodes);
    refreshBtnSftp.addEventListener("click", fetchNodes);

    // Setup SFTP upload button
    const sftpUploadBtn = document.getElementById("sftp-upload");
    const sftpFileInput = document.getElementById("sftp-file-input");

    sftpUploadBtn.addEventListener("click", () => sftpFileInput.click());
    sftpFileInput.addEventListener("change", (e) => {
        if (sftpBrowser && sftpBrowser.socket && sftpBrowser.sessionId) {
            const files = e.target.files;
            if (files && files.length > 0) {
                sftpBrowser.uploadFile(files[0]);
            }
        } else {
            alert("Not connected to SFTP");
        }
        e.target.value = "";
    });

    // Tab switching
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const tabName = btn.dataset.tab;
            switchTab(tabName);

            // Create separate socket for SFTP when switching to SFTP tab
            if (tabName === "sftp" && selected_node_id) {
                if (!sftpSocket) {
                    if (!sftpBrowser) {
                        sftpBrowser = new SFTPBrowser(wsEndpoint);
                    }
                    sftpSocket = connectSFTP();
                }
            }
        });
    });

    fullscreenBtn.addEventListener("click", () => {
        const container = document.documentElement;
        if (!document.fullscreenElement) {
            container.requestFullscreen().catch((err) => {
                log(`Failed to enter fullscreen: ${err.message}`);
            });
        } else {
            document.exitFullscreen().catch((err) => {
                log(`Failed to exit fullscreen: ${err.message}`);
            });
        }
    });

    [term, fitAddon] = setup_terminal();

    term.onData((data) => {
        if (credentialMode === "username") {
            handleUsernameKeystroke(data, true); // requires password after username
            return;
        }

        if (credentialMode === "username-only") {
            handleUsernameKeystroke(data, false); // no password required
            return;
        }

        if (credentialMode === "password") {
            handlePasswordKeystroke(data);
            return;
        }

        if (socket && socket.is_connected() && !!selected_node_id && !!session_id) {
            socket.send_ssh_tunnel_data(selected_node_id, session_id, data, 0);
        }
    });

    term.onResize(({ cols, rows }) => {
        fitAddon.fit();
        if (socket && socket.is_connected() && !!selected_node_id && !!session_id) {
            socket.send_ssh_terminal_resize(selected_node_id, session_id, cols, rows, 0);
        }
    });

    const resizeObserver = new ResizeObserver(() => {
        fitAddon.fit();
        if (socket && socket.is_connected() && !!selected_node_id && !!session_id) {
            socket.send_ssh_terminal_resize(selected_node_id, session_id, term.cols, term.rows);
        }
    });

    resizeObserver.observe(terminalHost);

    terminalHost.addEventListener("click", () => {
        term.focus();
    });

    setup().then(fetchNodes);
});
