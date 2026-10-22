//! Lines of a pipe, each at most [`MAX_LINE`] bytes long.

use std::io;
use std::pin::Pin;
use std::task::Poll;

use tokio::io::{AsyncRead, ReadBuf};

/// The longest line returned, in bytes, not counting its `\n`.
pub(super) const MAX_LINE: usize = 1024 * 1024;

/// The size of one read.
const CHUNK: usize = 64 * 1024;

/// One line read.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Line {
    /// A line, without its `\n`.
    Complete(Vec<u8>),
    /// A line longer than [`MAX_LINE`], whose bytes were discarded.
    Skipped,
}

/// Reads `\n`-terminated lines, holding at most [`MAX_LINE`] bytes of a line
/// and [`CHUNK`] bytes read ahead; a longer line is discarded as it is read.
/// An unterminated line at the end is discarded.
pub(super) struct LineReader<R> {
    inner: R,
    buf: Box<[u8]>,
    /// The bytes of `buf` not handled yet.
    start: usize,
    end: usize,
    /// The start of the line being read.
    line: Vec<u8>,
    /// Whether the line being read is over-long and discarded.
    skipping: bool,
    eof: bool,
}

impl<R: AsyncRead + Unpin> LineReader<R> {
    pub(super) fn new(inner: R) -> Self {
        Self {
            inner,
            buf: vec![0; CHUNK].into_boxed_slice(),
            start: 0,
            end: 0,
            line: Vec::new(),
            skipping: false,
            eof: false,
        }
    }

    /// Returns the next line, or `None` at the end.
    ///
    /// Cancel safe: a call dropped before it returns loses nothing.
    pub(super) async fn next(&mut self) -> io::Result<Option<Line>> {
        loop {
            if self.start == self.end {
                if self.eof {
                    return Ok(None);
                }
                let read = read_some(&mut self.inner, &mut self.buf).await?;
                self.start = 0;
                self.end = read;
                if read == 0 {
                    self.eof = true;
                    self.line = Vec::new();
                    self.skipping = false;
                    return Ok(None);
                }
            }
            let chunk = &self.buf[self.start..self.end];
            if let Some(newline) = chunk.iter().position(|&b| b == b'\n') {
                self.start += newline + 1;
                if std::mem::take(&mut self.skipping) || self.line.len() + newline > MAX_LINE {
                    self.line = Vec::new();
                    return Ok(Some(Line::Skipped));
                }
                self.line.extend_from_slice(&chunk[..newline]);
                return Ok(Some(Line::Complete(std::mem::take(&mut self.line))));
            }
            self.start = self.end;
            if self.skipping {
                continue;
            }
            if self.line.len() + chunk.len() > MAX_LINE {
                self.line = Vec::new();
                self.skipping = true;
            } else {
                self.line.extend_from_slice(chunk);
            }
        }
    }

    /// Returns how many bytes the reader holds, read ahead or of a line.
    #[cfg(test)]
    fn held(&self) -> usize {
        self.buf.len() + self.line.capacity()
    }
}

/// Reads once into `buf`; cancel safe.
async fn read_some<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    std::future::poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn lines(input: &[u8]) -> Vec<Line> {
        let mut reader = LineReader::new(input);
        let mut lines = Vec::new();
        while let Some(line) = reader.next().await.expect("read") {
            lines.push(line);
        }
        lines
    }

    #[tokio::test]
    async fn lines_are_split_at_newlines() {
        assert_eq!(
            lines(b"a\n\nbc\nunterminated").await,
            [
                Line::Complete(b"a".to_vec()),
                Line::Complete(Vec::new()),
                Line::Complete(b"bc".to_vec()),
            ]
        );
        assert_eq!(lines(b"").await, Vec::new());
    }

    #[tokio::test]
    async fn a_line_of_the_limit_is_returned_and_a_longer_one_skipped() {
        let mut input = vec![b'a'; MAX_LINE];
        input.push(b'\n');
        input.extend(vec![b'b'; MAX_LINE + 1]);
        input.push(b'\n');
        input.extend(b"after\n");
        // Over the limit by exactly the newline's position in a chunk.
        input.extend(vec![b'c'; CHUNK * 16 + 1]);
        input.push(b'\n');
        input.extend(b"last\n");
        let lines = lines(&input).await;
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], Line::Complete(vec![b'a'; MAX_LINE]));
        assert_eq!(lines[1], Line::Skipped);
        assert_eq!(lines[2], Line::Complete(b"after".to_vec()));
        assert_eq!(lines[3], Line::Skipped);
        assert_eq!(lines[4], Line::Complete(b"last".to_vec()));
    }

    /// Returns its chunks, one per read, and then waits forever.
    struct Chunks(std::collections::VecDeque<Vec<u8>>);

    impl AsyncRead for Chunks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.0.pop_front() {
                Some(chunk) => {
                    buf.put_slice(&chunk);
                    Poll::Ready(Ok(()))
                }
                None => Poll::Pending,
            }
        }
    }

    #[tokio::test]
    async fn an_over_long_line_is_not_held_and_reading_is_cancel_safe() {
        let wait = std::time::Duration::from_millis(100);
        let chunks = (0..16 * MAX_LINE / CHUNK)
            .map(|_| vec![b'x'; CHUNK])
            .collect();
        let mut reader = LineReader::new(Chunks(chunks));
        // Every chunk is read, and the read waiting for more is dropped.
        assert!(tokio::time::timeout(wait, reader.next()).await.is_err());
        assert!(reader.skipping);
        assert!(reader.held() <= CHUNK + 2 * MAX_LINE, "{}", reader.held());

        reader.inner.0.push_back(b"x\nnext\npartial".to_vec());
        assert_eq!(reader.next().await.expect("read"), Some(Line::Skipped));
        assert_eq!(
            reader.next().await.expect("read"),
            Some(Line::Complete(b"next".to_vec()))
        );
        assert!(tokio::time::timeout(wait, reader.next()).await.is_err());
        reader.inner.0.push_back(b" line\n".to_vec());
        assert_eq!(
            reader.next().await.expect("read"),
            Some(Line::Complete(b"partial line".to_vec()))
        );
    }
}
