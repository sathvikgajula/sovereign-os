//! Minimal stderr logging for RT setup (never called from metronome hot path).

pub(crate) fn rt_log_fmt(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write;

    struct Buf {
        data: [u8; 128],
        pos: usize,
    }

    impl Write for Buf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let take = s.len().min(self.data.len() - self.pos);
            self.data[self.pos..self.pos + take].copy_from_slice(&s.as_bytes()[..take]);
            self.pos += take;
            Ok(())
        }
    }

    let mut buf = Buf {
        data: [0u8; 128],
        pos: 0,
    };
    let _ = buf.write_fmt(args);
    if buf.pos > 0 {
        unsafe {
            libc::write(2, buf.data.as_ptr() as *const libc::c_void, buf.pos);
            libc::write(2, b"\n".as_ptr() as *const libc::c_void, 1);
        }
    }
}

#[macro_export]
macro_rules! rt_log {
    ($($arg:tt)*) => {
        $crate::log::rt_log_fmt(format_args!($($arg)*))
    };
}
