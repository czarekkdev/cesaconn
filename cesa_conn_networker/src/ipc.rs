// Inter-Process Communication (IPC) Module
//
// This module provides secure local socket communication between CesaConn processes.
// It implements a Unix domain socket-based IPC system with the following features:
// - Secure pipe creation with proper permissions (0o600)
// - Daemon detection and lifecycle management
// - Action-based message protocol for different operations
// - Async/await support with cancellation token integration
//
// TODO:
// - Implement types for different IPC actions
// - Add IPC client functionality
// - Add IPC daemon functionality
// - Add Windows support (named pipes)
// TODO LATER:
// - Add SELinux / AppArmor policy support for better security
// - add change SocketAddr trusted addrs to just Ipv4 since its lighter (4 bytes)

/// List of trusted process names that are allowed to connect to the IPC daemon
///
/// This constant defines which processes are authorized to communicate with
/// the IPC daemon. Peer verification is performed using SO_PEERCRED to ensure
/// that only trusted processes can connect.
///
/// # Security Note
/// This list should be kept minimal and only include processes that have a
/// legitimate need to communicate with the daemon. Adding untrusted processes
/// could lead to security vulnerabilities.
const TRUSTED_PROCESSES: &[&str] = &["cesa_conn_tui", "cesa_conn_gui"];

use crate::auth::Keys;
use crate::auth::Salts;
use std::fmt;
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::{
    fs::{Permissions, read_dir, read_to_string, remove_file, set_permissions},
    path::Path,
    process::id,
};
use std::{
    io::{Read, Write},
    sync::Arc,
};
#[cfg(unix)]
use std::{net::Ipv4Addr, os::unix::fs::PermissionsExt};
use tokio::select;
#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};
use tokio_util::future::FutureExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Action types for IPC messages
///
/// Each action type represents a different operation that can be requested
/// through the IPC system. The action type is sent as the first byte of
/// every IPC message.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum ActionType {
    /// Default action - no specific operation
    Default = 0x00,
    /// Request to update the authentication password
    UpdateAuthPassword = 0x01,
    /// Request to update the data encryption password
    UpdateDataPassword = 0x02,
    /// Request to add a new trusted device
    AddTrustedDevice = 0x03,
    /// Request to synchronize data with other devices
    SyncData = 0x04,
}

impl ActionType {
    /// Converts a raw u8 wire byte into an ActionType variant.
    ///
    /// Returns None for unknown values rather than panicking — the caller decides
    /// whether to fall back to Default or reject the packet entirely.
    ///
    /// # Arguments
    /// * `v` - The raw byte value received over the wire
    ///
    /// # Returns
    /// * `Some(ActionType)` - If the byte matches a known action type
    /// * `None` - If the byte is unknown
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::UpdateAuthPassword),
            0x02 => Some(Self::UpdateDataPassword),
            0x03 => Some(Self::AddTrustedDevice),
            0x04 => Some(Self::SyncData),
            _ => None,
        }
    }
}

/// Errors that can occur during IPC operations
///
/// This enum covers all possible error conditions that can arise during
/// IPC communication, from system-level failures to protocol violations.
#[derive(Debug, PartialEq)]
pub enum IpcErrors {
    /// UID not found in /proc/self/status
    UIDNotFound,
    /// Failed to read /proc/self/status
    FailedToRead,
    /// Failed to get UID for socket path
    FailedToGetUID,
    /// Failed to fetch socket path
    FailedToFetchSocketPath,
    /// Failed to read process directory
    FailedToReadprocessDirectory,
    /// Failed to filter map during process enumeration
    FailedToFilterMap,
    /// Failed to fetch processes
    FailedToFechProcesses,
    /// Failed to get name from our own process
    FailedToGetSelfName,
    /// Failed to fetch process name
    FailedToReadProcessName,
    /// Failed to check if process exists
    FailedToCheckIfProcessExists,
    /// Failed to remove file
    FailedToRemoveFile,
    /// Failed to bind socket
    FailedToBindSocket,
    /// Failed to set permissions
    FailedToSetPermissions,
    /// Daemon is already running
    DaemonAlreadyRunning,
    /// Failed to check if daemon is running
    FailedToCheckIfRunning,
    /// Failed to connect to the pipe
    FailedToConnectToPipe,
    /// Failed to check stream state
    FailedToCheckStreamState,
    /// Stream is not writable
    NotWritable,
    /// Failed to write data to stream
    FailedToWriteToStream,
    /// Secure pipe is not created yet
    PipeNotCreated,
    /// Failed to create secure pipe
    FailedToCreateSecurePipe,
    /// Failed to accept ipc connection
    FailedToAcceptConnection,
    /// Failed to read data from ipc stream
    FailedToReadDataFromStream,
    /// Confirmation byte not received
    ConfirmationByteNotReceived,
    /// Failed to get data from client
    FailedToRecvData,
    /// Failed to handle data from ipc client
    FailedToHandleData,
    /// Data from client is too large
    DataTooLarge,
    /// No data received
    NoData,
    /// Daemon is not running yet
    DaemonIsNotRunning,
    /// Failed to get peer credentials
    FailedToGetPeerCred,
    /// Failed to get process pid
    FailedToGetPid,
    /// Failed to get process name
    FailedToGetProcessName,
    /// Failed to get peer name
    FailedToGetPeerName,
    /// Unauthorized peer tried to connect
    UnauthorizedPeer,
    /// Size of data is wrong (fixed data size)
    WrongDataSize,
}

impl fmt::Display for IpcErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::UIDNotFound => "UID not found in /proc/self/status",
            Self::FailedToRead => "failed to read /proc/self/status",
            Self::FailedToGetUID => "failed to get UID for socket path",
            Self::FailedToFetchSocketPath => "failed to fetch socket path",
            Self::FailedToReadprocessDirectory => "failed to read process directory",
            Self::FailedToFilterMap => "failed to filter map",
            Self::FailedToFechProcesses => "failed to fetch processes",
            Self::FailedToGetSelfName => "failed to get name from our own process",
            Self::FailedToReadProcessName => "failed to fetch process name",
            Self::FailedToCheckIfProcessExists => "failed to check if process exists",
            Self::FailedToRemoveFile => "failed to remove file",
            Self::FailedToBindSocket => "failed to bind socket",
            Self::FailedToSetPermissions => "failed to set permissions",
            Self::DaemonAlreadyRunning => "daemon is already running",
            Self::FailedToCheckIfRunning => "failed to check if daemon is running",
            Self::FailedToConnectToPipe => "failed to connect to the pipe",
            Self::FailedToCheckStreamState => "failed to check stream state",
            Self::NotWritable => "stream is not writable",
            Self::FailedToWriteToStream => "failed to write data to stream",
            Self::PipeNotCreated => "secure pipe is not created yet",
            Self::FailedToCreateSecurePipe => "failed to create secure pipe",
            Self::FailedToAcceptConnection => "failed to accept ipc connection",
            Self::FailedToReadDataFromStream => "failed to read data from ipc stream",
            Self::ConfirmationByteNotReceived => "confirmation byte not received",
            Self::FailedToRecvData => "failed to get data from client",
            Self::FailedToHandleData => "failed to handle data from ipc client",
            Self::DataTooLarge => "data from cllient is too large",
            Self::NoData => "there's no data",
            Self::DaemonIsNotRunning => "daemon is not running yet",
            Self::FailedToGetPeerCred => "failed to get peer cred",
            Self::FailedToGetPid => "failed to get process pid",
            Self::FailedToGetProcessName => "failed to get process name",
            Self::FailedToGetPeerName => "failed to get peer name",
            Self::UnauthorizedPeer => "unauthorized peer tired to connect",
            Self::WrongDataSize => "data size is not correct",
        };
        write!(f, "{}", msg)
    }
}

/// Gets the current process UID from /proc/self/status
///
/// This function reads the Linux /proc filesystem to determine the current
/// user ID, which is used to construct the socket path for IPC.
///
/// # Returns
/// * `Ok(u32)` - The UID of the current process
/// * `Err(IpcErrors)` - If reading /proc/self/status fails or UID cannot be parsed
#[cfg(unix)]
fn getuid() -> Result<u32, IpcErrors> {
    std::fs::read_to_string("/proc/self/status")
        .map_err(|_| IpcErrors::FailedToRead)?
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|uid| uid.parse().ok())
        .ok_or_else(|| IpcErrors::UIDNotFound)
}

/// Constructs the socket path for IPC communication
///
/// Returns the path where the Unix domain socket should be created,
/// based on the current user's UID.
///
/// # Returns
/// * `Ok(String)` - The socket path (e.g., "/run/user/1000/cesa_conn.sock")
/// * `Err(IpcErrors)` - If UID cannot be obtained
#[cfg(unix)]
fn socket_path() -> Result<String, IpcErrors> {
    let uid = getuid().map_err(|_| IpcErrors::FailedToGetUID)?;
    Ok(format!("/run/user/{}/cesa_conn.sock", uid))
}

/// Gets the name of the current process from /proc/self/comm
///
/// Reads the process name from the Linux /proc filesystem, which is used
/// for daemon detection and process management.
///
/// # Returns
/// * `Ok(String)` - The process name (trimmed of whitespace)
/// * `Err(IpcErrors)` - If reading /proc/self/comm fails
#[cfg(unix)]
pub fn get_self_name() -> Result<String, IpcErrors> {
    Ok(read_to_string("/proc/self/comm")
        .map_err(|_| IpcErrors::FailedToGetSelfName)?
        .trim()
        .to_string())
}

/// Gets a list of all running process PIDs (excluding current process)
///
/// Reads the /proc directory to enumerate all running processes, filtering
/// out the current process PID.
///
/// # Returns
/// * `Ok(Vec<String>)` - List of process PIDs as strings
/// * `Err(IpcErrors)` - If reading /proc fails
#[cfg(unix)]
pub fn get_processes() -> Result<Vec<String>, IpcErrors> {
    let process_dir = read_dir("/proc/").map_err(|_| IpcErrors::FailedToReadprocessDirectory)?;

    let processes: Vec<String> = process_dir
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            name.parse::<u32>().ok()?;
            Some(name)
        })
        .filter(|e| *e != id().to_string())
        .collect();

    Ok(processes)
}

/// Gets the name of a process by its PID
///
/// Reads the process name from /proc/{pid}/comm for the given process ID.
///
/// # Arguments
/// * `pid` - The process ID as a string
///
/// # Returns
/// * `Ok(String)` - The process name (trimmed of whitespace)
/// * `Err(IpcErrors)` - If reading /proc/{pid}/comm fails
#[cfg(unix)]
pub fn get_process_name(pid: String) -> Result<String, IpcErrors> {
    Ok(read_to_string(format!("/proc/{}/comm", pid))
        .map_err(|_| IpcErrors::FailedToReadProcessName)?
        .trim()
        .to_string())
}

/// Checks if a process with the given name is currently running
///
/// Enumerates all running processes and checks if any match the given name.
///
/// # Arguments
/// * `name` - The process name to search for
///
/// # Returns
/// * `Ok(bool)` - true if process is running, false otherwise
/// * `Err(IpcErrors)` - If process enumeration fails
#[cfg(unix)]
pub fn process_exists(name: String) -> Result<bool, IpcErrors> {
    let processes = get_processes().map_err(|_| {
        error!("Failed to fetch processes");
        IpcErrors::FailedToFechProcesses
    })?;

    Ok(processes.iter().any(|pid| {
        get_process_name(pid.to_string())
            .map(|n| n == name)
            .unwrap_or(false)
    }))
}

/// Checks if the CesaConn daemon is currently running
///
/// Determines if the daemon is running by checking both:
/// 1. If the socket file exists
/// 2. If a process with the daemon's name is running
///
/// # Returns
/// * `Ok(bool)` - true if daemon is running, false otherwise
/// * `Err(IpcErrors)` - If checking daemon status fails
#[cfg(unix)]
pub fn is_running() -> Result<bool, IpcErrors> {
    let path = socket_path().map_err(|_| IpcErrors::FailedToFetchSocketPath)?;

    // Use hardcoded process name for reliable daemon detection
    let proc_name = String::from("cesa_conn_networker");

    debug!(socket_path = %path, proc_name = %proc_name, "checking if daemon is running");

    let process_exists =
        process_exists(proc_name).map_err(|_| IpcErrors::FailedToCheckIfProcessExists)?;

    if Path::new(&path).exists() {
        if process_exists {
            info!("daemon is running (socket exists and process found)");
            return Ok(true);
        } else {
            warn!("socket exists but process not found, stale socket");
        }
    }

    debug!("daemon is not running");
    Ok(false)
}

/// Gets the name of the peer process connected to the Unix socket
///
/// This function uses SO_PEERCRED to get the peer's credentials and then
/// looks up the process name from /proc/{pid}/comm.
///
/// # Arguments
/// * `connection` - &tokio::net::UnixStream - The Unix stream connection
///
/// # Returns
/// * `Ok(String)` - The peer process name
/// * `Err(IpcErrors)` - If getting peer credentials or process name fails
#[cfg(unix)]
fn get_peer_name(connection: &tokio::net::UnixStream) -> Result<String, IpcErrors> {
    debug!("getting peer credentials using SO_PEERCRED");

    let ucreed = connection
        .peer_cred()
        .map_err(|_| IpcErrors::FailedToGetPeerCred)?;

    let pid = ucreed.pid().ok_or(IpcErrors::FailedToGetPid)?;

    debug!(peer_pid = pid, "looking up peer process name");

    let peer_name =
        get_process_name(pid.to_string()).map_err(|_| IpcErrors::FailedToGetProcessName)?;

    debug!(peer_pid = pid, peer_name = %peer_name, "peer name retrieved");

    Ok(peer_name)
}

/// Creates a secure Unix domain socket for IPC communication
///
/// This function creates a Unix domain socket with restricted permissions (0o600)
/// for secure inter-process communication. It checks if a daemon is already
/// running and returns an error if so.
///
/// # Security Considerations
/// - Socket permissions are set to 0o600 (owner read/write only)
/// - Stale socket files are cleaned up before creating new ones
/// - Daemon running check prevents multiple instances
///
/// # Returns
/// * `Ok(UnixListener)` - The bound socket listener ready to accept connections
/// * `Err(IpcErrors)` - If socket creation fails or daemon is already running
#[cfg(unix)]
use tokio::net::UnixListener;
use zeroize::{Zeroize, Zeroizing};
pub fn create_secure_pipe() -> Result<UnixListener, IpcErrors> {
    let path = socket_path().map_err(|_| IpcErrors::FailedToFetchSocketPath)?;

    debug!(socket_path = %path, "checking if daemon is already running");

    let is_daemon_running = is_running().map_err(|_| IpcErrors::FailedToCheckIfRunning)?;

    if !is_daemon_running {
        if Path::new(&path).exists() {
            info!(socket_path = %path, "removing stale socket file");
            remove_file(&path).map_err(|_| IpcErrors::FailedToRemoveFile)?;
        }
    } else {
        warn!("daemon is already running, cannot create new socket");
        return Err(IpcErrors::DaemonAlreadyRunning);
    }

    info!(socket_path = %path, "creating new Unix domain socket");

    let socket = UnixListener::bind(&path).map_err(|_| IpcErrors::FailedToBindSocket)?;

    debug!(socket_path = %path, "setting socket permissions to 0o600");
    set_permissions(&path, Permissions::from_mode(0o600))
        .map_err(|_| IpcErrors::FailedToSetPermissions)?;

    info!(socket_path = %path, "secure pipe created successfully");

    Ok(socket)
}

/// Converts a 4-byte slice into a `SocketAddr` with port 0.
///
/// # Arguments
/// * `data` - A 4-byte slice containing an IPv4 address in network byte order
///
/// # Returns
/// A `SocketAddr` wrapping the parsed IPv4 address with port set to 0
pub fn get_ip_from_bytes(data: &[u8]) -> std::net::SocketAddr {
    let mut addr_bytes = [0u8; size_of::<Ipv4Addr>()];
    addr_bytes.copy_from_slice(&data);

    let addr = Ipv4Addr::from_octets(addr_bytes);
    std::net::SocketAddr::new(std::net::IpAddr::V4(addr), 0000)
}

/// Converts a `SocketAddr` to a 4-byte IPv4 address array.
///
/// IPv4-mapped IPv6 addresses are canonicalized to their V4 form first.
/// Returns `[0u8; 4]` for any non-IPv4 address.
///
/// # Arguments
/// * `socket_addr` - The socket address to convert
///
/// # Returns
/// A 4-byte array of IPv4 address octets
pub fn get_bytes_from_ip(socket_addr: &std::net::SocketAddr) -> [u8; size_of::<Ipv4Addr>()] {
    match socket_addr.ip().to_canonical() {
        IpAddr::V4(v4) => v4.octets(),
        _ => [0u8; 4],
    }
}

/// Receives and processes an IPC message from a client
///
/// This function handles incoming IPC connections, reads the message,
/// and processes it based on the action type. The protocol is:
/// 1. Verify peer identity using SO_PEERCRED
/// 2. Read 8-byte size prefix
/// 3. Send confirmation byte (0x01)
/// 4. Read the actual message data
/// 5. Process based on action type
///
/// # Arguments
/// * `keys` - Arc<RwLock<Keys>> - Authentication and data encryption keys (shared reference)
/// * `trusted_addrs` - Arc<RwLock<Vec<std::net::SocketAddr>>> - Trusted socket addresses
/// * `incoming_connection` - Tuple of (UnixStream, SocketAddr) for the connection
/// * `salts` - Arc<RwLock<Salts>> - Authentication and data encryption salts (shared reference)
///
/// # Returns
/// * `Ok(())` - Message processed successfully
/// * `Err(IpcErrors)` - If reading or processing fails
#[cfg(unix)]
pub async fn ipc_recv(
    keys: Arc<RwLock<Keys>>,
    trusted_addrs: Arc<RwLock<Vec<std::net::SocketAddr>>>,
    incoming_connection: (tokio::net::UnixStream, tokio::net::unix::SocketAddr),
    salts: Arc<RwLock<Salts>>,
) -> Result<(), IpcErrors> {
    let (mut stream, _addr) = incoming_connection;

    // Verify peer identity using SO_PEERCRED for security
    let peer_name = get_peer_name(&stream).map_err(|_| IpcErrors::FailedToGetPeerName)?;

    debug!(peer_name = %peer_name, "Verifying peer identity");

    if !TRUSTED_PROCESSES.contains(&peer_name.as_str()) {
        warn!(peer_name = %peer_name, "Unauthorized peer attempted to connect");
        return Err(IpcErrors::UnauthorizedPeer);
    }

    info!(peer_name = %peer_name, "Authorized peer connected, reading message size");

    let mut size_buffer = [0u8; 8];
    stream
        .read_exact(&mut size_buffer)
        .await
        .map_err(|_| IpcErrors::FailedToReadDataFromStream)?;

    let size = u64::from_le_bytes(size_buffer);

    debug!(
        size,
        "message size read, validating and sending confirmation"
    );

    // Validate message size to prevent DoS attacks
    if size > 64 * 1024 {
        warn!(size, "Message too large, rejecting");
        return Err(IpcErrors::DataTooLarge);
    } else if size == 0 {
        warn!("Empty message received, rejecting");
        return Err(IpcErrors::NoData);
    }

    let confirmation_byte = [1u8];

    stream
        .write_all(&confirmation_byte)
        .await
        .map_err(|_| IpcErrors::FailedToWriteToStream)?;

    debug!(size, "reading message data");
    let mut buffer = vec![0u8; size as usize];

    stream
        .read_exact(&mut buffer)
        .await
        .map_err(|_| IpcErrors::FailedToReadDataFromStream)?;

    debug!(data_len = buffer.len(), "message data received, processing");

    handle_data_server(
        buffer,
        trusted_addrs,
        keys.clone(),
        salts.clone(),
        (stream, _addr),
    )
    .await
    .map_err(|_| IpcErrors::FailedToHandleData)?;

    Ok(())
}

/// IPC daemon that listens for incoming connections and spawns handlers
///
/// This function runs the main IPC daemon loop, accepting connections
/// and spawning async tasks to handle each one. It supports graceful
/// shutdown via cancellation token.
///
/// # Architecture
/// - Each connection is handled in a separate async task
/// - Cancellation token allows graceful shutdown
/// - Peer verification is performed before accepting connections
///
/// # Arguments
/// * `keys` - Arc<RwLock<Keys>> - Authentication and data encryption keys (shared reference)
/// * `trusted_addrs` - Arc<RwLock<Vec<std::net::SocketAddr>>> - Trusted socket addresses
/// * `cancellation_token` - CancellationToken for graceful shutdown
/// * `salts` - Arc<RwLock<Salts>> - Authentication and data encryption salts (shared reference)
///
/// # Returns
/// * `Ok(())` - Daemon shut down gracefully
/// * `Err(IpcErrors)` - If socket creation fails
#[cfg(unix)]
pub async fn ipc_daemon(
    keys: Arc<RwLock<Keys>>,
    trusted_addrs: Arc<RwLock<Vec<std::net::SocketAddr>>>,
    cancellation_token: CancellationToken,
    salts: Arc<RwLock<Salts>>,
) -> Result<(), IpcErrors> {
    let socket = create_secure_pipe().map_err(|_| IpcErrors::FailedToCreateSecurePipe)?;
    info!("IPC daemon started, listening for connections");

    loop {
        let cancellation_token_clone = cancellation_token.clone();
        let keys_clone = keys.clone();
        let salts_clone = salts.clone();
        let trusted_addrs_clone = trusted_addrs.clone();

        debug!("waiting for incoming IPC connection or cancellation signal");

        let incoming_connection = select! {
            _ = cancellation_token.cancelled() => {
                info!("IPC daemon shutting down gracefully");
                return Ok(());
            }
            result = socket.accept() => {
                result.map_err(|_| IpcErrors::FailedToAcceptConnection)?
            }
        };

        debug!("IPC connection accepted, spawning handler task");

        tokio::spawn(async move {
            select! {
                _ = cancellation_token_clone.cancelled() => {
                    info!("cancellation token fired mid-handler, dropping ipc_recv task");
                }
                result = ipc_recv(keys_clone, trusted_addrs_clone, incoming_connection, salts_clone) => {
                    match result {
                        Ok(()) => debug!("ipc_recv completed successfully"),
                        Err(e) => error!(error = %e, "ipc_recv returned an error"),
                    }
                }
            }
        });
    }
}

/// Windows placeholder for secure pipe creation
///
/// This is a placeholder for Windows support. On Windows, named pipes
/// should be used instead of Unix domain sockets.
///
/// # Returns
/// * `Ok(())` - Always succeeds (placeholder)
#[cfg(target_os = "windows")]
pub fn create_secure_pipe() -> Result<(), IpcErrors> {
    Ok(())
}

/// Handles incoming IPC data based on the action type
///
/// This function processes received IPC messages and performs the appropriate
/// action based on the action type specified in the first byte of the data.
///
/// # Arguments
/// * `data` - Vec<u8> - The received data (first byte is action type)
/// * `trusted_addrs` - Arc<RwLock<Vec<std::net::SocketAddr>>> - Shared list of trusted addresses
///
/// # Returns
/// * `Ok(())` - Data handled successfully
/// * `Err(IpcErrors)` - If handling fails
///
/// # Supported Actions
/// - `AddTrustedDevice` (0x03): Adds a new trusted device address from bytes 1-5
/// - `SyncData` (0x04): Synchronizes data with other devices (not yet implemented)
/// - `UpdateAuthPassword` (0x01): Updates auth key and salt (bytes 1-32: key, 33-64: salt; total payload must be 65 bytes)
/// - `UpdateDataPassword` (0x02): Updates data encryption key and salt (bytes 1-32: key, 33-64: salt; total payload must be 65 bytes)
/// - `Default` (0x00): No operation performed
/// - Unknown values: Ignored with warning
pub async fn handle_data_server(
    mut data: Vec<u8>,
    trusted_addrs: Arc<RwLock<Vec<std::net::SocketAddr>>>,
    keys: Arc<RwLock<Keys>>,
    salts: Arc<RwLock<Salts>>,
    incoming_connection: (tokio::net::UnixStream, tokio::net::unix::SocketAddr),
) -> Result<(), IpcErrors> {
    // TODO: handle key changes, data syncing with UI, and forwarding to cesa_conn_system controller when action type doesn't match

    let (mut stream, _addr) = incoming_connection;

    match ActionType::from_u8(data[0]) {
        Some(ActionType::AddTrustedDevice) => {
            debug!("Processing AddTrustedDevice action");

            let socket_addr = get_ip_from_bytes(&data[1..size_of::<Ipv4Addr>() + 1]);
            let addr = socket_addr.ip();

            debug!(%addr, "Adding new trusted device address");

            trusted_addrs.write().await.push(socket_addr);

            info!(%addr, "Successfully added trusted device");
        }
        Some(ActionType::SyncData) => {
            let mut addrs_bytes_vec: Vec<[u8; 4]> = trusted_addrs
                .read()
                .await
                .iter()
                .map(|addr| get_bytes_from_ip(addr))
                .collect();

            let addrs_bytes = Zeroizing::new(addrs_bytes_vec.concat());
            let size_bytes = (addrs_bytes.len() + 8).to_le_bytes();

            addrs_bytes_vec.zeroize();

            stream
                .write_all(&size_bytes)
                .await
                .map_err(|_| IpcErrors::FailedToWriteToStream)?;

            stream
                .write_all(&addrs_bytes)
                .await
                .map_err(|_| IpcErrors::FailedToWriteToStream)?;
        }
        Some(ActionType::UpdateAuthPassword) => {
            debug!("Processing UpdateAuthPassword action (not yet implemented)");
            // TODO: Implement auth password update

            if data.len() != 65 {
                return Err(IpcErrors::WrongDataSize);
            }

            keys.write().await.a_key.clone_from_slice(&data[1..33]);

            salts.write().await.a_salt.clone_from_slice(&data[33..65]);
        }
        Some(ActionType::UpdateDataPassword) => {
            debug!("Processing UpdateDataPassword action (not yet implemented)");
            // TODO: Implement data password update

            if data.len() != 65 {
                return Err(IpcErrors::WrongDataSize);
            }

            keys.write().await.d_key.clone_from_slice(&data[1..33]);

            salts.write().await.d_salt.clone_from_slice(&data[33..65]);
        }
        Some(ActionType::Default) => {
            debug!("Received Default action (no operation)");
        }
        None => {
            warn!(
                action_byte = data[0],
                "Received unknown action type, ignoring"
            );
        }
    }

    data.zeroize();
    Ok(())
}

/// Client-side handler that applies an IPC action to local shared state.
///
/// This is the client-side counterpart to `handle_data_server`. It parses the raw
/// payload and updates `keys`, `salts`, and `trusted_addrs` in place based on the
/// action type.
///
/// # Arguments
/// * `action_type` - The action to perform
/// * `data` - Raw message payload; byte 0 is NOT the action byte here — the caller
///   already separated the action. Layout varies by action type (see below).
/// * `trusted_addrs` - Shared list of trusted peer addresses
/// * `keys` - Shared authentication and data encryption keys
/// * `salts` - Shared authentication and data encryption salts
///
/// # Returns
/// * `Ok(())` - Action applied successfully
/// * `Err(IpcErrors)` - If the payload is malformed
///
/// # Payload layouts
/// - `AddTrustedDevice`: bytes 1-4 contain the IPv4 address (4 bytes). TODO: incomplete.
/// - `SyncData`: bytes 1-128 are key+salt material (64 bytes keys, 64 bytes salts);
///   bytes 129+ are a packed list of 4-byte IPv4 addresses.
/// - `UpdateAuthPassword`, `UpdateDataPassword`, `Default`: not yet handled here.
pub async fn ipc_action(
    action_type: ActionType,
    data: &[u8],
    trusted_addrs: Arc<RwLock<Vec<std::net::SocketAddr>>>,
    keys: Arc<RwLock<Keys>>,
    salts: Arc<RwLock<Salts>>,
) -> Result<(), IpcErrors> {
    match action_type {
        ActionType::AddTrustedDevice => {
            // bytes 1..=4 hold the IPv4 address octets
            let mut addr_bytes = [0u8; size_of::<Ipv4Addr>()];
            addr_bytes.copy_from_slice(&data[1..size_of::<Ipv4Addr>() + 1]);

            let addr = Ipv4Addr::from_octets(addr_bytes);
            let socket_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(addr), 0000);
            // TODO: push socket_addr into trusted_addrs
        }

        ActionType::SyncData => {
            // 64 bytes keys (a_key || d_key) + 64 bytes salts (a_salt || d_salt) = 128 bytes
            let fixed_sizes = 128;

            if data.len() < fixed_sizes + 1 {
                return Err(IpcErrors::WrongDataSize);
            }

            // remaining bytes after the fixed block must be a whole number of IPv4 addresses
            let dynamic_size = data.len() - 129;

            if dynamic_size % size_of::<Ipv4Addr>() != 0 {
                return Err(IpcErrors::WrongDataSize);
            }

            let mut sk_data = Zeroizing::new([0u8; 128]);
            sk_data.copy_from_slice(&data[1..fixed_sizes + 1]);

            let mut keys_new_bytes = Zeroizing::new([0u8; 64]);
            let mut salts_new_bytes = Zeroizing::new([0u8; 64]);

            keys_new_bytes.copy_from_slice(&sk_data[..64]);
            salts_new_bytes.copy_from_slice(&sk_data[64..]);

            salts
                .write()
                .await
                .update(Salts::from_ref(&salts_new_bytes));

            keys.write().await.update(Keys::from_ref(&keys_new_bytes));

            // bytes 129+ are packed 4-byte IPv4 addresses
            let addresses: Vec<std::net::SocketAddr> = data[129..]
                .chunks_exact(size_of::<Ipv4Addr>())
                .map(|addr_bytes| get_ip_from_bytes(addr_bytes))
                .collect();

            let trusted_addrs_lock = trusted_addrs.write().await;

            trusted_addrs_lock.extend(
                addresses
                    .into_iter()
                    .filter(|addr| !trusted_addrs_lock.contains(addr)),
            );
        }
    }

    Ok(())
}

/// Sends an IPC message to the daemon
///
/// This function sends a message to the IPC daemon using the following protocol:
/// 1. Check if daemon is running
/// 2. Connect to the socket
/// 3. Send message size (8 bytes)
/// 4. Wait for confirmation byte
/// 5. Send the actual message data
///
/// # Arguments
/// * `action_type` - ActionType - The type of action being requested
/// * `data` - &[u8] - The payload data to send
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(IpcErrors)` - If sending fails or daemon not available

#[cfg(unix)]
pub fn ipc_send(action_type: ActionType, data: &[u8]) -> Result<(), IpcErrors> {
    let path = socket_path().map_err(|_| IpcErrors::FailedToFetchSocketPath)?;

    debug!("Checking if IPC daemon is running");

    let is_daemon_running = is_running().map_err(|_| IpcErrors::FailedToCheckIfRunning)?;

    if !is_daemon_running {
        warn!("IPC daemon is not running, cannot send message");
        return Err(IpcErrors::DaemonIsNotRunning);
    }

    info!(action_type = ?action_type, data_len = data.len(), "connecting to IPC daemon");

    let mut stream = UnixStream::connect(path).map_err(|_| IpcErrors::FailedToConnectToPipe)?;
    let mut final_data = Vec::with_capacity(data.len() + 1);

    final_data.push(action_type as u8);
    final_data.extend_from_slice(&data);

    let len = u64::to_le_bytes(final_data.len() as u64);

    debug!(total_len = final_data.len(), "sending message size");
    stream
        .write_all(&len)
        .map_err(|_| IpcErrors::FailedToWriteToStream)?;

    debug!("waiting for confirmation byte from daemon");
    let mut buffer = [0u8];

    stream
        .read_exact(&mut buffer)
        .map_err(|_| IpcErrors::FailedToReadDataFromStream)?;

    if buffer[0] == 0x00 {
        error!("Received 0x00 confirmation byte, daemon rejected message");
        return Err(IpcErrors::ConfirmationByteNotReceived);
    }

    debug!(
        confirmation = buffer[0],
        "confirmation received, sending message data"
    );
    stream
        .write_all(&final_data)
        .map_err(|_| IpcErrors::FailedToWriteToStream)?;

    info!(action_type = ?action_type, "message sent successfully to IPC daemon");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that ActionType::from_u8 correctly converts known values
    #[test]
    fn test_action_type_from_u8() {
        assert_eq!(ActionType::from_u8(0x00), Some(ActionType::Default));
        assert_eq!(
            ActionType::from_u8(0x01),
            Some(ActionType::UpdateAuthPassword)
        );
        assert_eq!(
            ActionType::from_u8(0x02),
            Some(ActionType::UpdateDataPassword)
        );
        assert_eq!(
            ActionType::from_u8(0x03),
            Some(ActionType::AddTrustedDevice)
        );
        assert_eq!(ActionType::from_u8(0x04), Some(ActionType::SyncData));
        assert_eq!(ActionType::from_u8(0xFF), None);
        assert_eq!(ActionType::from_u8(0x05), None);
    }

    /// Test that ActionType enum values match their repr(u8) values
    #[test]
    fn test_action_type_repr() {
        assert_eq!(ActionType::Default as u8, 0x00);
        assert_eq!(ActionType::UpdateAuthPassword as u8, 0x01);
        assert_eq!(ActionType::UpdateDataPassword as u8, 0x02);
        assert_eq!(ActionType::AddTrustedDevice as u8, 0x03);
        assert_eq!(ActionType::SyncData as u8, 0x04);
    }

    /// Test that all IpcErrors variants produce non-empty Display strings
    #[test]
    fn test_ipc_errors_display() {
        let errors = vec![
            IpcErrors::UIDNotFound,
            IpcErrors::FailedToRead,
            IpcErrors::FailedToGetUID,
            IpcErrors::FailedToFetchSocketPath,
            IpcErrors::FailedToReadprocessDirectory,
            IpcErrors::FailedToFilterMap,
            IpcErrors::FailedToFechProcesses,
            IpcErrors::FailedToGetSelfName,
            IpcErrors::FailedToReadProcessName,
            IpcErrors::FailedToCheckIfProcessExists,
            IpcErrors::FailedToRemoveFile,
            IpcErrors::FailedToBindSocket,
            IpcErrors::FailedToSetPermissions,
            IpcErrors::DaemonAlreadyRunning,
            IpcErrors::FailedToCheckIfRunning,
            IpcErrors::FailedToConnectToPipe,
            IpcErrors::FailedToCheckStreamState,
            IpcErrors::NotWritable,
            IpcErrors::FailedToWriteToStream,
            IpcErrors::PipeNotCreated,
            IpcErrors::FailedToCreateSecurePipe,
            IpcErrors::FailedToAcceptConnection,
            IpcErrors::FailedToReadDataFromStream,
            IpcErrors::ConfirmationByteNotReceived,
            IpcErrors::FailedToRecvData,
            IpcErrors::FailedToHandleData,
            IpcErrors::DataTooLarge,
            IpcErrors::NoData,
            IpcErrors::DaemonIsNotRunning,
            IpcErrors::FailedToGetPeerCred,
            IpcErrors::FailedToGetPid,
            IpcErrors::FailedToGetProcessName,
            IpcErrors::FailedToGetPeerName,
            IpcErrors::UnauthorizedPeer,
        ];

        for error in errors {
            assert!(
                !error.to_string().is_empty(),
                "Error {:?} produced empty string",
                error
            );
        }
    }

    /// Test that ActionType variants are equal to themselves
    #[test]
    fn test_action_type_equality() {
        assert_eq!(ActionType::Default, ActionType::Default);
        assert_eq!(
            ActionType::UpdateAuthPassword,
            ActionType::UpdateAuthPassword
        );
        assert_eq!(
            ActionType::UpdateDataPassword,
            ActionType::UpdateDataPassword
        );
    }

    /// Test that ActionType variants are not equal to each other
    #[test]
    fn test_action_type_inequality() {
        assert_ne!(ActionType::Default, ActionType::UpdateAuthPassword);
        assert_ne!(ActionType::Default, ActionType::UpdateDataPassword);
        assert_ne!(
            ActionType::UpdateAuthPassword,
            ActionType::UpdateDataPassword
        );
    }

    /// Test that IpcErrors variants are equal to themselves
    #[test]
    fn test_ipc_errors_equality() {
        assert_eq!(IpcErrors::UIDNotFound, IpcErrors::UIDNotFound);
        assert_eq!(IpcErrors::FailedToRead, IpcErrors::FailedToRead);
        assert_eq!(
            IpcErrors::DaemonAlreadyRunning,
            IpcErrors::DaemonAlreadyRunning
        );
    }

    /// Test that IpcErrors variants are not equal to each other
    #[test]
    fn test_ipc_errors_inequality() {
        assert_ne!(IpcErrors::UIDNotFound, IpcErrors::FailedToRead);
        assert_ne!(IpcErrors::FailedToRead, IpcErrors::DaemonAlreadyRunning);
        assert_ne!(IpcErrors::DaemonAlreadyRunning, IpcErrors::UIDNotFound);
    }

    /// Test that ActionType can be used in match statements
    #[test]
    fn test_action_type_match() {
        let action = ActionType::UpdateAuthPassword;
        let result = match action {
            ActionType::Default => "default",
            ActionType::UpdateAuthPassword => "auth",
            ActionType::UpdateDataPassword => "data",
            ActionType::AddTrustedDevice => "add_device",
            ActionType::SyncData => "sync",
        };
        assert_eq!(result, "auth");
    }

    /// Test that unknown action types are handled gracefully
    #[test]
    fn test_unknown_action_type() {
        let unknown = 0x99u8;
        let result = ActionType::from_u8(unknown);
        assert!(result.is_none());
    }

    /// Test that all action types can be converted to u8 and back
    #[test]
    fn test_action_type_roundtrip() {
        let actions = [
            ActionType::Default,
            ActionType::UpdateAuthPassword,
            ActionType::UpdateDataPassword,
            ActionType::AddTrustedDevice,
            ActionType::SyncData,
        ];

        for action in actions {
            let byte = action as u8;
            let converted = ActionType::from_u8(byte);
            assert_eq!(converted, Some(action));
        }
    }

    /// Test that IpcErrors implements Debug correctly
    #[test]
    fn test_ipc_errors_debug() {
        let error = IpcErrors::DaemonAlreadyRunning;
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("DaemonAlreadyRunning"));
    }

    /// Test that ActionType implements Debug correctly
    #[test]
    fn test_action_type_debug() {
        let action = ActionType::UpdateAuthPassword;
        let debug_str = format!("{:?}", action);
        assert!(debug_str.contains("UpdateAuthPassword"));
    }

    /// Test that IpcErrors can be assigned (move semantics work correctly)
    #[test]
    fn test_ipc_errors_assignment() {
        let error = IpcErrors::FailedToRead;
        // This test verifies that the error type can be used in contexts
        // where assignment might be needed (e.g., error propagation)
        let error_copy = error; // Simple assignment works
        assert_eq!(error_copy, IpcErrors::FailedToRead);
    }

    /// Test that ActionType can be assigned (move semantics work correctly)
    #[test]
    fn test_action_type_assignment() {
        let action = ActionType::UpdateDataPassword;
        let action_copy = action; // Simple assignment works
        assert_eq!(action_copy, ActionType::UpdateDataPassword);
    }

    /// Test edge case: maximum u8 value for ActionType
    #[test]
    fn test_action_type_max_u8() {
        let max_value = 0xFFu8;
        let result = ActionType::from_u8(max_value);
        assert!(result.is_none());
    }

    /// Test edge case: zero value for ActionType
    #[test]
    fn test_action_type_zero() {
        let zero_value = 0x00u8;
        let result = ActionType::from_u8(zero_value);
        assert_eq!(result, Some(ActionType::Default));
    }

    /// Test that IpcErrors Display strings are human-readable
    #[test]
    fn test_ipc_errors_human_readable() {
        let error = IpcErrors::DaemonAlreadyRunning;
        let display_str = error.to_string();
        assert!(display_str.len() > 0);
        assert!(display_str.contains("daemon") || display_str.contains("running"));
    }

    /// Test that ActionType Display is not implemented (compile-time check)
    #[test]
    fn test_action_type_no_display() {
        // This test verifies that ActionType does NOT implement Display
        // If it did, this would compile and we'd want to know
        let action = ActionType::Default;
        // The following line should NOT compile:
        // let _ = action.to_string();
        // Since we can't test for non-compilation, we just verify
        // that we can use Debug instead
        let _ = format!("{:?}", action);
    }

    /// Test that new action types (AddTrustedDevice, SyncData) work correctly
    #[test]
    fn test_new_action_types() {
        assert_eq!(
            ActionType::from_u8(0x03),
            Some(ActionType::AddTrustedDevice)
        );
        assert_eq!(ActionType::from_u8(0x04), Some(ActionType::SyncData));
        assert_eq!(ActionType::AddTrustedDevice as u8, 0x03);
        assert_eq!(ActionType::SyncData as u8, 0x04);
    }

    /// Test that new error types produce valid Display strings
    #[test]
    fn test_new_error_types_display() {
        let new_errors = vec![
            IpcErrors::FailedToGetPeerCred,
            IpcErrors::FailedToGetPid,
            IpcErrors::FailedToGetProcessName,
            IpcErrors::FailedToGetPeerName,
            IpcErrors::UnauthorizedPeer,
        ];

        for error in new_errors {
            assert!(!error.to_string().is_empty());
        }
    }

    /// Test that DaemonIsNotRunning error works correctly
    #[test]
    fn test_daemon_is_not_running_error() {
        let error = IpcErrors::DaemonIsNotRunning;
        let display_str = error.to_string();
        assert!(display_str.contains("not running"));
    }

    /// Test that DataTooLarge and NoData errors work correctly
    #[test]
    fn test_data_validation_errors() {
        let too_large = IpcErrors::DataTooLarge;
        let no_data = IpcErrors::NoData;

        assert!(!too_large.to_string().is_empty());
        assert!(!no_data.to_string().is_empty());
    }

    /// Test that all action types are covered in roundtrip
    #[test]
    fn test_all_action_types_roundtrip() {
        let all_actions = [
            ActionType::Default,
            ActionType::UpdateAuthPassword,
            ActionType::UpdateDataPassword,
            ActionType::AddTrustedDevice,
            ActionType::SyncData,
        ];

        for action in all_actions {
            let byte = action as u8;
            let converted = ActionType::from_u8(byte);
            assert_eq!(converted, Some(action), "Failed for action: {:?}", action);
        }
    }

    /// Test that ActionType variants are not equal to each other (including new types)
    #[test]
    fn test_action_type_inequality_extended() {
        assert_ne!(ActionType::Default, ActionType::AddTrustedDevice);
        assert_ne!(ActionType::Default, ActionType::SyncData);
        assert_ne!(ActionType::UpdateAuthPassword, ActionType::AddTrustedDevice);
        assert_ne!(ActionType::UpdateAuthPassword, ActionType::SyncData);
        assert_ne!(ActionType::UpdateDataPassword, ActionType::AddTrustedDevice);
        assert_ne!(ActionType::UpdateDataPassword, ActionType::SyncData);
        assert_ne!(ActionType::AddTrustedDevice, ActionType::SyncData);
    }

    /// Test that all IpcErrors variants are unique
    #[test]
    fn test_all_ipc_errors_unique() {
        let all_errors = [
            IpcErrors::UIDNotFound,
            IpcErrors::FailedToRead,
            IpcErrors::FailedToGetUID,
            IpcErrors::FailedToFetchSocketPath,
            IpcErrors::FailedToReadprocessDirectory,
            IpcErrors::FailedToFilterMap,
            IpcErrors::FailedToFechProcesses,
            IpcErrors::FailedToGetSelfName,
            IpcErrors::FailedToReadProcessName,
            IpcErrors::FailedToCheckIfProcessExists,
            IpcErrors::FailedToRemoveFile,
            IpcErrors::FailedToBindSocket,
            IpcErrors::FailedToSetPermissions,
            IpcErrors::DaemonAlreadyRunning,
            IpcErrors::FailedToCheckIfRunning,
            IpcErrors::FailedToConnectToPipe,
            IpcErrors::FailedToCheckStreamState,
            IpcErrors::NotWritable,
            IpcErrors::FailedToWriteToStream,
            IpcErrors::PipeNotCreated,
            IpcErrors::FailedToCreateSecurePipe,
            IpcErrors::FailedToAcceptConnection,
            IpcErrors::FailedToReadDataFromStream,
            IpcErrors::ConfirmationByteNotReceived,
            IpcErrors::FailedToRecvData,
            IpcErrors::FailedToHandleData,
            IpcErrors::DataTooLarge,
            IpcErrors::NoData,
            IpcErrors::DaemonIsNotRunning,
            IpcErrors::FailedToGetPeerCred,
            IpcErrors::FailedToGetPid,
            IpcErrors::FailedToGetProcessName,
            IpcErrors::FailedToGetPeerName,
            IpcErrors::UnauthorizedPeer,
        ];

        // Verify all errors are unique by checking that no two are equal
        for (i, error1) in all_errors.iter().enumerate() {
            for (j, error2) in all_errors.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        error1, error2,
                        "Errors at indices {} and {} are equal",
                        i, j
                    );
                }
            }
        }
    }
}
