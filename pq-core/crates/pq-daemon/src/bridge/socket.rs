use std::os::unix::io::RawFd;

#[derive(Debug, Clone, Copy)]
pub enum SendAttempt {
    Wrote(usize),
    WouldBlock,
    Broken,
    Fatal(i32),
}

#[inline(always)]
unsafe fn errno_now() -> i32 {
    #[cfg(target_os = "macos")]
    {
        *libc::__error()
    }
    #[cfg(not(target_os = "macos"))]
    {
        *libc::__errno_location()
    }
}

pub fn prepare_metronome_socket(fd: RawFd) -> std::io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }

        #[cfg(target_os = "macos")]
        {
            let on: libc::c_int = 1;
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    Ok(())
}

#[inline(always)]
pub fn try_write(fd: RawFd, buf: &[u8]) -> SendAttempt {
    let len = buf.len();
    if len == 0 {
        return SendAttempt::Wrote(0);
    }

    let ret = unsafe {
        libc::write(fd, buf.as_ptr() as *const libc::c_void, len)
    };

    if ret >= 0 {
        return SendAttempt::Wrote(ret as usize);
    }

    let e = unsafe { errno_now() };

    match e {
        libc::EAGAIN => SendAttempt::WouldBlock,
        #[cfg(not(target_os = "macos"))]
        libc::EWOULDBLOCK => SendAttempt::WouldBlock,
        libc::EPIPE | libc::ECONNRESET | libc::ECONNREFUSED => SendAttempt::Broken,
        _ => SendAttempt::Fatal(e),
    }
}
