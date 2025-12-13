// Axel '0vercl0k' Souchet - May 30 2024
use std::io;

pub trait AddrSpace {
    fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<usize>;

    fn read_exact_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        let size = self.read_at(addr, buf)?;

        if size != buf.len() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("could read only {size} bytes instead of {}", buf.len()),
            ))
        } else {
            Ok(())
        }
    }

    fn try_read_exact_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<Option<()>> {
        let size = self.read_at(addr, buf)?;

        Ok(if size != buf.len() { None } else { Some(()) })
    }
}

impl<T> AddrSpace for Box<T>
where
    T: AddrSpace + ?Sized,
{
    fn read_at(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
        T::read_at(self, addr, buf)
    }
}
