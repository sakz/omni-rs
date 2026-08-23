pub fn available() -> bool {
    false
}

pub fn apply_keepalive(stream: &tokio::net::TcpStream, secs: u32) -> std::io::Result<()> {
    use tokio::net::TcpStream as S;
    let _ = (stream, secs);
    #[cfg(target_os = "linux")]
    unsafe {
        let fd = std::os::fd::AsRawFd::as_raw_fd(stream);
        let v: libc::c_int = 1;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, &v as *const _ as *const libc::c_void, std::mem::size_of_val(&v));
    }
    let _ = std::any::TypeId::of::<S>();
    Ok(())
}
