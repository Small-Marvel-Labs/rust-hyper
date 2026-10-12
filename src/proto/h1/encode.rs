use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io::IoSlice;

use bytes::buf::{Chain, Take};
use bytes::{Buf, Bytes, BytesMut};
use http::{
    header::{
        AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
        CONTENT_TYPE, HOST, MAX_FORWARDS, SET_COOKIE, TE, TRAILER, TRANSFER_ENCODING,
    },
    HeaderMap, HeaderName,
};

use super::io::WriteBuf;
use super::role::write_message_headers;
use crate::ext::{
    FieldSpacing, HeaderCaseMap, OriginalHeaderOrder, RawChunks, RawTrailers, TrailerSpacing,
};

type StaticBuf = &'static [u8];

/// Encoders to handle different Transfer-Encodings.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Encoder {
    kind: Kind,
    is_last: bool,
    raw_trailers: Option<(RawTrailers, Option<TrailerSpacing>)>,
    raw_chunks: Option<ChunkPlan>,
}

/// Where a chunked body being written stands in the [`RawChunks`] it follows, whose
/// first line is the next to write: each line written is dropped from it.
#[derive(Debug, Clone, PartialEq)]
struct ChunkPlan {
    record: RawChunks,
    /// The bytes still owed to the chunk being written.
    remaining: u64,
}

#[derive(Debug)]
pub(crate) struct EncodedBuf<B> {
    kind: BufKind<B>,
}

#[derive(Debug)]
pub(crate) struct NotEof(u64);

#[derive(Debug, PartialEq, Clone)]
enum Kind {
    /// An Encoder for when Transfer-Encoding includes `chunked`.
    Chunked(Option<Vec<HeaderName>>),
    /// An Encoder for when Content-Length is set.
    ///
    /// Enforces that the body is not longer than the Content-Length header.
    Length(u64),
    /// An Encoder for when neither Content-Length nor Chunked encoding is set.
    ///
    /// This is mostly only used with HTTP/1.0 with a length. This kind requires
    /// the connection to be closed when the body is finished.
    #[cfg(feature = "server")]
    CloseDelimited,
}

#[derive(Debug)]
enum BufKind<B> {
    Exact(B),
    Limited(Take<B>),
    Chunked(Chain<Chain<ChunkSize, B>, StaticBuf>),
    ChunkedEnd(StaticBuf),
    Trailers(Chain<Chain<Bytes, Bytes>, StaticBuf>),
    Segments(Segments),
}

/// Byte runs written in order: body data split and framed at recorded chunk sizes.
#[derive(Debug, Default)]
struct Segments(VecDeque<Bytes>);

/// Data shorter than this goes out copied in with the framing around it, so a body of
/// many small chunks is written as a few runs rather than as four per chunk.
const COPIED_DATA: usize = 1024;

impl Encoder {
    fn new(kind: Kind) -> Encoder {
        Encoder {
            kind,
            is_last: false,
            raw_trailers: None,
            raw_chunks: None,
        }
    }
    pub(crate) fn chunked() -> Encoder {
        Encoder::new(Kind::Chunked(None))
    }

    pub(crate) fn length(len: u64) -> Encoder {
        Encoder::new(Kind::Length(len))
    }

    #[cfg(feature = "server")]
    pub(crate) fn close_delimited() -> Encoder {
        Encoder::new(Kind::CloseDelimited)
    }

    pub(crate) fn into_chunked_with_trailing_fields(self, trailers: Vec<HeaderName>) -> Encoder {
        match self.kind {
            Kind::Chunked(_) => Encoder {
                kind: Kind::Chunked(Some(trailers)),
                is_last: self.is_last,
                raw_trailers: self.raw_trailers,
                raw_chunks: self.raw_chunks,
            },
            _ => self,
        }
    }

    /// Writes the trailers with the spelling, order and spacing `raw` records, once it does.
    pub(crate) fn with_raw_trailers(
        mut self,
        raw: Option<(RawTrailers, Option<TrailerSpacing>)>,
    ) -> Self {
        self.raw_trailers = raw;
        self
    }

    /// Writes a chunked body at the chunk sizes and with the chunk-size lines `raw` records.
    pub(crate) fn with_raw_chunks(mut self, raw: Option<RawChunks>) -> Self {
        self.raw_chunks = raw.map(|record| ChunkPlan {
            record,
            remaining: 0,
        });
        self
    }

    /// Whether a chunked body is written at recorded chunk sizes.
    pub(crate) fn has_raw_chunks(&self) -> bool {
        self.is_chunked() && self.raw_chunks.is_some()
    }

    /// Fails when the body ended inside a recorded chunk, whose size line is already out.
    pub(crate) fn check_raw_chunks_complete(&self) -> Result<(), NotEof> {
        match &self.raw_chunks {
            Some(plan) if self.is_chunked() && plan.remaining > 0 => Err(NotEof(plan.remaining)),
            _ => Ok(()),
        }
    }

    /// The last-chunk line, as recorded when a chunked body follows a record.
    fn last_chunk(&self) -> Bytes {
        self.raw_chunks
            .as_ref()
            .and_then(|plan| {
                plan.record
                    .lock()
                    .first()
                    .filter(|(size, _)| *size == 0)
                    .map(|(_, line)| {
                        let mut last = Vec::with_capacity(line.len() + 2);
                        last.extend_from_slice(line);
                        last.extend_from_slice(b"\r\n");
                        Bytes::from(last)
                    })
            })
            .unwrap_or_else(|| Bytes::from_static(b"0\r\n"))
    }

    pub(crate) fn is_eof(&self) -> bool {
        matches!(self.kind, Kind::Length(0))
    }

    #[cfg(feature = "server")]
    pub(crate) fn set_last(mut self, is_last: bool) -> Self {
        self.is_last = is_last;
        self
    }

    pub(crate) fn is_last(&self) -> bool {
        self.is_last
    }

    pub(crate) fn is_close_delimited(&self) -> bool {
        match self.kind {
            #[cfg(feature = "server")]
            Kind::CloseDelimited => true,
            _ => false,
        }
    }

    pub(crate) fn is_chunked(&self) -> bool {
        matches!(self.kind, Kind::Chunked(_))
    }

    pub(crate) fn end<B>(&self) -> Result<Option<EncodedBuf<B>>, NotEof> {
        match self.kind {
            Kind::Length(0) => Ok(None),
            Kind::Chunked(_) if self.raw_chunks.is_some() => {
                self.check_raw_chunks_complete()?;
                let end = [self.last_chunk(), Bytes::from_static(b"\r\n")];
                Ok(Some(EncodedBuf {
                    kind: BufKind::Segments(Segments(end.into())),
                }))
            }
            Kind::Chunked(_) => Ok(Some(EncodedBuf {
                kind: BufKind::ChunkedEnd(b"0\r\n\r\n"),
            })),
            #[cfg(feature = "server")]
            Kind::CloseDelimited => Ok(None),
            Kind::Length(n) => Err(NotEof(n)),
        }
    }

    pub(crate) fn encode<B>(&mut self, msg: B) -> EncodedBuf<B>
    where
        B: Buf,
    {
        let len = msg.remaining();
        debug_assert!(len > 0, "encode() called with empty buf");

        let kind = match &mut self.kind {
            Kind::Chunked(_) if self.raw_chunks.is_some() => {
                trace!("encoding chunked {}B at recorded chunk sizes", len);
                let plan = self.raw_chunks.as_mut().expect("raw chunks");
                BufKind::Segments(plan.encode(msg))
            }
            Kind::Chunked(_) => {
                trace!("encoding chunked {}B", len);
                let buf = ChunkSize::new(len)
                    .chain(msg)
                    .chain(b"\r\n" as &'static [u8]);
                BufKind::Chunked(buf)
            }
            Kind::Length(remaining) => {
                trace!("sized write, len = {}", len);
                if len as u64 > *remaining {
                    let limit = *remaining as usize;
                    *remaining = 0;
                    BufKind::Limited(msg.take(limit))
                } else {
                    *remaining -= len as u64;
                    BufKind::Exact(msg)
                }
            }
            #[cfg(feature = "server")]
            Kind::CloseDelimited => {
                trace!("close delimited write {}B", len);
                BufKind::Exact(msg)
            }
        };
        EncodedBuf { kind }
    }

    /// Encodes the chunked-body trailer section. Only fields listed in the
    /// message's `Trailer` header are written, unless `permissive` is set, in
    /// which case every valid trailer field is written as given (whether or not
    /// a `Trailer` header declared it).
    pub(crate) fn encode_trailers<B>(
        &self,
        trailers: HeaderMap,
        title_case_headers: bool,
        permissive: bool,
    ) -> Option<EncodedBuf<B>> {
        trace!("encoding trailers");
        match &self.kind {
            Kind::Chunked(allowed_trailer_fields)
                if permissive || allowed_trailer_fields.is_some() =>
            {
                let allowed_set: Option<HashSet<&HeaderName>> = if permissive {
                    None
                } else {
                    allowed_trailer_fields
                        .as_ref()
                        .map(|fields| fields.iter().collect())
                };

                let mut cur_name = None;
                let mut allowed_trailers = HeaderMap::new();

                for (opt_name, value) in trailers {
                    if let Some(n) = opt_name {
                        cur_name = Some(n);
                    }
                    let name = cur_name.as_ref().expect("current header name");

                    if allowed_set.as_ref().map_or(true, |set| set.contains(name)) {
                        if is_valid_trailer_field(name) {
                            allowed_trailers.append(name, value);
                        } else {
                            debug!("trailer field is not valid: {}", &name);
                        }
                    } else {
                        debug!("trailer header name not found in trailer header: {}", &name);
                    }
                }

                let mut buf = Vec::new();
                write_message_headers(
                    &allowed_trailers,
                    &trailer_extensions(self.raw_trailers.as_ref()),
                    &mut buf,
                    title_case_headers,
                );

                if buf.is_empty() {
                    return None;
                }

                Some(EncodedBuf {
                    kind: BufKind::Trailers(
                        self.last_chunk().chain(Bytes::from(buf)).chain(b"\r\n"),
                    ),
                })
            }
            Kind::Chunked(None) => {
                debug!("attempted to encode trailers, but the trailer header is not set");
                None
            }
            _ => {
                debug!("attempted to encode trailers for non-chunked response");
                None
            }
        }
    }

    pub(super) fn encode_and_end<B>(&self, msg: B, dst: &mut WriteBuf<EncodedBuf<B>>) -> bool
    where
        B: Buf,
    {
        let len = msg.remaining();
        debug_assert!(len > 0, "encode() called with empty buf");

        match self.kind {
            Kind::Chunked(_) => {
                trace!("encoding chunked {}B", len);
                let buf = ChunkSize::new(len)
                    .chain(msg)
                    .chain(b"\r\n0\r\n\r\n" as &'static [u8]);
                dst.buffer(buf);
                !self.is_last
            }
            Kind::Length(remaining) => {
                use std::cmp::Ordering;

                trace!("sized write, len = {}", len);
                match (len as u64).cmp(&remaining) {
                    Ordering::Equal => {
                        dst.buffer(msg);
                        !self.is_last
                    }
                    Ordering::Greater => {
                        dst.buffer(msg.take(remaining as usize));
                        !self.is_last
                    }
                    Ordering::Less => {
                        dst.buffer(msg);
                        false
                    }
                }
            }
            #[cfg(feature = "server")]
            Kind::CloseDelimited => {
                trace!("close delimited write {}B", len);
                dst.buffer(msg);
                false
            }
        }
    }
}

impl ChunkPlan {
    /// Frames `msg` as the rest of the chunk being written and the recorded chunks after
    /// it; bytes past the record go out as one chunk.
    fn encode<B: Buf>(&mut self, mut msg: B) -> Segments {
        let mut lines = self.record.lock();
        let mut written = 0;
        let mut out = Segments::default();
        let mut run = BytesMut::new();
        while msg.has_remaining() {
            if self.remaining == 0 {
                match lines.get(written) {
                    Some((size, line)) if *size > 0 => {
                        run.extend_from_slice(line);
                        run.extend_from_slice(b"\r\n");
                        self.remaining = *size;
                        written += 1;
                    }
                    _ => {
                        let len = msg.remaining();
                        run.extend_from_slice(format!("{len:X}\r\n").as_bytes());
                        out.push_data(&mut run, msg.copy_to_bytes(len));
                        run.extend_from_slice(b"\r\n");
                        break;
                    }
                }
            }
            let len = msg.remaining().min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
            out.push_data(&mut run, msg.copy_to_bytes(len));
            self.remaining -= len as u64;
            if self.remaining == 0 {
                run.extend_from_slice(b"\r\n");
            }
        }
        if !run.is_empty() {
            out.0.push_back(run.freeze());
        }
        lines.drain(..written);
        out
    }
}

impl Segments {
    /// Adds `data` to `run`, the bytes copied together, when it is short; otherwise ends
    /// `run` and adds `data` as it is.
    fn push_data(&mut self, run: &mut BytesMut, data: Bytes) {
        if data.len() < COPIED_DATA {
            run.extend_from_slice(&data);
        } else {
            if !run.is_empty() {
                self.0.push_back(run.split().freeze());
            }
            self.0.push_back(data);
        }
    }
}

impl Buf for Segments {
    fn remaining(&self) -> usize {
        self.0.iter().map(Bytes::len).sum()
    }

    fn chunk(&self) -> &[u8] {
        self.0.front().map_or(&[], |b| b.as_ref())
    }

    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            let front = self.0.front_mut().expect("advance past the end of segments");
            if cnt < front.len() {
                front.advance(cnt);
                return;
            }
            cnt -= front.len();
            self.0.pop_front();
        }
    }

    fn chunks_vectored<'t>(&'t self, dst: &mut [IoSlice<'t>]) -> usize {
        let mut n = 0;
        for (slot, b) in dst.iter_mut().zip(self.0.iter().filter(|b| !b.is_empty())) {
            *slot = IoSlice::new(b);
            n += 1;
        }
        n
    }
}

/// The case and order extensions that write trailers as `raw` recorded them, once it has.
fn trailer_extensions(raw: Option<&(RawTrailers, Option<TrailerSpacing>)>) -> http::Extensions {
    let mut extensions = http::Extensions::new();
    if let Some((raw, spacing)) = raw {
        let Some(fields) = raw.0.get() else {
            return extensions;
        };
        let spacing = spacing
            .as_ref()
            .and_then(|spacing| spacing.0.get())
            .filter(|spacing| spacing.len() == fields.len());
        let mut case = HeaderCaseMap::default();
        let mut order = OriginalHeaderOrder::default();
        for (at, (spelling, _)) in fields.iter().enumerate() {
            if let Ok(name) = HeaderName::from_bytes(spelling) {
                match spacing.map(|spacing| &spacing[at]) {
                    Some((separator, trailing)) => case.append_spaced(
                        &name,
                        spelling.clone(),
                        FieldSpacing {
                            separator: separator.clone(),
                            trailing: trailing.clone(),
                        },
                    ),
                    None => case.append_parsed(&name, spelling.clone()),
                }
                order.append(name);
            }
        }
        extensions.insert(case);
        extensions.insert(order);
    }
    extensions
}

fn is_valid_trailer_field(name: &HeaderName) -> bool {
    !matches!(
        *name,
        AUTHORIZATION
            | CACHE_CONTROL
            | CONTENT_ENCODING
            | CONTENT_LENGTH
            | CONTENT_RANGE
            | CONTENT_TYPE
            | HOST
            | MAX_FORWARDS
            | SET_COOKIE
            | TRAILER
            | TRANSFER_ENCODING
            | TE
    )
}

impl<B> Buf for EncodedBuf<B>
where
    B: Buf,
{
    #[inline]
    fn remaining(&self) -> usize {
        match &self.kind {
            BufKind::Exact(b) => b.remaining(),
            BufKind::Limited(b) => b.remaining(),
            BufKind::Chunked(b) => b.remaining(),
            BufKind::ChunkedEnd(b) => b.remaining(),
            BufKind::Trailers(b) => b.remaining(),
            BufKind::Segments(b) => b.remaining(),
        }
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        match &self.kind {
            BufKind::Exact(b) => b.chunk(),
            BufKind::Limited(b) => b.chunk(),
            BufKind::Chunked(b) => b.chunk(),
            BufKind::ChunkedEnd(b) => b.chunk(),
            BufKind::Trailers(b) => b.chunk(),
            BufKind::Segments(b) => b.chunk(),
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        match &mut self.kind {
            BufKind::Exact(b) => b.advance(cnt),
            BufKind::Limited(b) => b.advance(cnt),
            BufKind::Chunked(b) => b.advance(cnt),
            BufKind::ChunkedEnd(b) => b.advance(cnt),
            BufKind::Trailers(b) => b.advance(cnt),
            BufKind::Segments(b) => b.advance(cnt),
        }
    }

    #[inline]
    fn chunks_vectored<'t>(&'t self, dst: &mut [IoSlice<'t>]) -> usize {
        match &self.kind {
            BufKind::Exact(b) => b.chunks_vectored(dst),
            BufKind::Limited(b) => b.chunks_vectored(dst),
            BufKind::Chunked(b) => b.chunks_vectored(dst),
            BufKind::ChunkedEnd(b) => b.chunks_vectored(dst),
            BufKind::Trailers(b) => b.chunks_vectored(dst),
            BufKind::Segments(b) => b.chunks_vectored(dst),
        }
    }
}

#[cfg(target_pointer_width = "32")]
const USIZE_BYTES: usize = 4;

#[cfg(target_pointer_width = "64")]
const USIZE_BYTES: usize = 8;

// each byte will become 2 hex
const CHUNK_SIZE_MAX_BYTES: usize = USIZE_BYTES * 2;

#[derive(Clone, Copy)]
struct ChunkSize {
    bytes: [u8; CHUNK_SIZE_MAX_BYTES + 2],
    pos: u8,
    len: u8,
}

impl ChunkSize {
    fn new(len: usize) -> ChunkSize {
        use std::fmt::Write;
        let mut size = ChunkSize {
            bytes: [0; CHUNK_SIZE_MAX_BYTES + 2],
            pos: 0,
            len: 0,
        };
        write!(&mut size, "{len:X}\r\n").expect("CHUNK_SIZE_MAX_BYTES should fit any usize");
        size
    }
}

impl Buf for ChunkSize {
    #[inline]
    fn remaining(&self) -> usize {
        (self.len - self.pos).into()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        &self.bytes[self.pos.into()..self.len.into()]
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining());
        self.pos += cnt as u8; // just asserted cnt fits in u8
    }
}

impl fmt::Debug for ChunkSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkSize")
            .field("bytes", &&self.bytes[..self.len.into()])
            .field("pos", &self.pos)
            .finish()
    }
}

impl fmt::Write for ChunkSize {
    fn write_str(&mut self, num: &str) -> fmt::Result {
        use std::io::Write;
        (&mut self.bytes[self.len.into()..])
            .write_all(num.as_bytes())
            .expect("&mut [u8].write() cannot error");
        self.len += num.len() as u8; // safe because bytes is never bigger than 256
        Ok(())
    }
}

impl<B: Buf> From<B> for EncodedBuf<B> {
    fn from(buf: B) -> Self {
        EncodedBuf {
            kind: BufKind::Exact(buf),
        }
    }
}

impl<B: Buf> From<Take<B>> for EncodedBuf<B> {
    fn from(buf: Take<B>) -> Self {
        EncodedBuf {
            kind: BufKind::Limited(buf),
        }
    }
}

impl<B: Buf> From<Chain<Chain<ChunkSize, B>, StaticBuf>> for EncodedBuf<B> {
    fn from(buf: Chain<Chain<ChunkSize, B>, StaticBuf>) -> Self {
        EncodedBuf {
            kind: BufKind::Chunked(buf),
        }
    }
}

impl fmt::Display for NotEof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "early end, expected {} more bytes", self.0)
    }
}

impl std::error::Error for NotEof {}

#[cfg(test)]
mod tests {
    use bytes::BufMut;
    use http::{
        header::{
            AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
            CONTENT_TYPE, HOST, MAX_FORWARDS, SET_COOKIE, TE, TRAILER, TRANSFER_ENCODING,
        },
        HeaderMap, HeaderName, HeaderValue,
    };

    use super::super::io::Cursor;
    use super::Encoder;

    #[test]
    fn chunked() {
        let mut encoder = Encoder::chunked();
        let mut dst = Vec::new();

        let msg1 = b"foo bar".as_ref();
        let buf1 = encoder.encode(msg1);
        dst.put(buf1);
        assert_eq!(dst, b"7\r\nfoo bar\r\n");

        let msg2 = b"baz quux herp".as_ref();
        let buf2 = encoder.encode(msg2);
        dst.put(buf2);

        assert_eq!(dst, b"7\r\nfoo bar\r\nD\r\nbaz quux herp\r\n");

        let end = encoder.end::<Cursor<Vec<u8>>>().unwrap().unwrap();
        dst.put(end);

        assert_eq!(
            dst,
            b"7\r\nfoo bar\r\nD\r\nbaz quux herp\r\n0\r\n\r\n".as_ref()
        );
    }

    #[test]
    fn length() {
        let max_len = 8;
        let mut encoder = Encoder::length(max_len as u64);
        let mut dst = Vec::new();

        let msg1 = b"foo bar".as_ref();
        let buf1 = encoder.encode(msg1);
        dst.put(buf1);

        assert_eq!(dst, b"foo bar");
        assert!(!encoder.is_eof());
        encoder.end::<()>().unwrap_err();

        let msg2 = b"baz".as_ref();
        let buf2 = encoder.encode(msg2);
        dst.put(buf2);

        assert_eq!(dst.len(), max_len);
        assert_eq!(dst, b"foo barb");
        assert!(encoder.is_eof());
        assert!(encoder.end::<()>().unwrap().is_none());
    }

    #[cfg(feature = "server")]
    #[test]
    fn eof() {
        let mut encoder = Encoder::close_delimited();
        let mut dst = Vec::new();

        let msg1 = b"foo bar".as_ref();
        let buf1 = encoder.encode(msg1);
        dst.put(buf1);

        assert_eq!(dst, b"foo bar");
        assert!(!encoder.is_eof());
        encoder.end::<()>().unwrap();

        let msg2 = b"baz".as_ref();
        let buf2 = encoder.encode(msg2);
        dst.put(buf2);

        assert_eq!(dst, b"foo barbaz");
        assert!(!encoder.is_eof());
        encoder.end::<()>().unwrap();
    }

    #[test]
    fn chunked_with_valid_trailers() {
        let encoder = Encoder::chunked();
        let trailers = vec![HeaderName::from_static("chunky-trailer")];
        let encoder = encoder.into_chunked_with_trailing_fields(trailers);

        let headers = HeaderMap::from_iter(vec![
            (
                HeaderName::from_static("chunky-trailer"),
                HeaderValue::from_static("header data"),
            ),
            (
                HeaderName::from_static("should-not-be-included"),
                HeaderValue::from_static("oops"),
            ),
        ]);

        let buf1 = encoder
            .encode_trailers::<&[u8]>(headers, false, false)
            .unwrap();

        let mut dst = Vec::new();
        dst.put(buf1);
        assert_eq!(dst, b"0\r\nchunky-trailer: header data\r\n\r\n");
    }

    #[test]
    fn chunked_with_multiple_trailer_headers() {
        let encoder = Encoder::chunked();
        let trailers = vec![
            HeaderName::from_static("chunky-trailer"),
            HeaderName::from_static("chunky-trailer-2"),
        ];
        let encoder = encoder.into_chunked_with_trailing_fields(trailers);

        let headers = HeaderMap::from_iter(vec![
            (
                HeaderName::from_static("chunky-trailer"),
                HeaderValue::from_static("header data"),
            ),
            (
                HeaderName::from_static("chunky-trailer-2"),
                HeaderValue::from_static("more header data"),
            ),
        ]);

        let buf1 = encoder
            .encode_trailers::<&[u8]>(headers, false, false)
            .unwrap();

        let mut dst = Vec::new();
        dst.put(buf1);
        assert_eq!(
            dst,
            b"0\r\nchunky-trailer: header data\r\nchunky-trailer-2: more header data\r\n\r\n"
        );
    }

    #[test]
    fn chunked_with_duplicate_trailer_values() {
        let encoder = Encoder::chunked();
        let trailers = vec![HeaderName::from_static("chunky-trailer")];
        let encoder = encoder.into_chunked_with_trailing_fields(trailers);

        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("chunky-trailer"),
            HeaderValue::from_static("first"),
        );
        headers.append(
            HeaderName::from_static("chunky-trailer"),
            HeaderValue::from_static("second"),
        );

        let buf1 = encoder
            .encode_trailers::<&[u8]>(headers, false, false)
            .unwrap();

        let mut dst = Vec::new();
        dst.put(buf1);
        assert_eq!(
            dst,
            b"0\r\nchunky-trailer: first\r\nchunky-trailer: second\r\n\r\n"
        );
    }

    #[test]
    fn chunked_with_no_trailer_header() {
        let encoder = Encoder::chunked();

        let headers = HeaderMap::from_iter(vec![(
            HeaderName::from_static("chunky-trailer"),
            HeaderValue::from_static("header data"),
        )]);

        assert!(encoder
            .encode_trailers::<&[u8]>(headers.clone(), false, false)
            .is_none());

        let trailers = vec![];
        let encoder = encoder.into_chunked_with_trailing_fields(trailers);

        assert!(encoder
            .encode_trailers::<&[u8]>(headers, false, false)
            .is_none());
    }

    #[test]
    fn chunked_with_invalid_trailers() {
        let encoder = Encoder::chunked();

        let trailers = vec![
            AUTHORIZATION,
            CACHE_CONTROL,
            CONTENT_ENCODING,
            CONTENT_LENGTH,
            CONTENT_RANGE,
            CONTENT_TYPE,
            HOST,
            MAX_FORWARDS,
            SET_COOKIE,
            TRAILER,
            TRANSFER_ENCODING,
            TE,
        ];
        let encoder = encoder.into_chunked_with_trailing_fields(trailers);

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("header data"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("header data"));
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("header data"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("header data"));
        headers.insert(CONTENT_RANGE, HeaderValue::from_static("header data"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("header data"));
        headers.insert(HOST, HeaderValue::from_static("header data"));
        headers.insert(MAX_FORWARDS, HeaderValue::from_static("header data"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("header data"));
        headers.insert(TRAILER, HeaderValue::from_static("header data"));
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("header data"));
        headers.insert(TE, HeaderValue::from_static("header data"));

        assert!(encoder
            .encode_trailers::<&[u8]>(headers, true, false)
            .is_none());
    }

    #[test]
    fn chunked_with_title_case_headers() {
        let encoder = Encoder::chunked();
        let trailers = vec![HeaderName::from_static("chunky-trailer")];
        let encoder = encoder.into_chunked_with_trailing_fields(trailers);

        let headers = HeaderMap::from_iter(vec![(
            HeaderName::from_static("chunky-trailer"),
            HeaderValue::from_static("header data"),
        )]);
        let buf1 = encoder
            .encode_trailers::<&[u8]>(headers, true, false)
            .unwrap();

        let mut dst = Vec::new();
        dst.put(buf1);
        assert_eq!(dst, b"0\r\nChunky-Trailer: header data\r\n\r\n");
    }

    #[test]
    fn chunked_trailers_case_insensitive_matching() {
        // Regression test for issue #4010: HTTP/1.1 trailers are case-sensitive
        //
        // Previously, the Trailer header values were stored as HeaderValue (preserving case)
        // and compared against HeaderName (which is always lowercase). This caused trailers
        // declared as "Chunky-Trailer" to not match actual trailers sent as "chunky-trailer".
        //
        // The fix converts Trailer header values to HeaderName during parsing, which
        // normalizes the case and enables proper case-insensitive matching.
        //
        // Note: HeaderName::from_static() requires lowercase input. In real usage,
        // HeaderName::from_bytes() is used to parse the Trailer header value, which
        // normalizes mixed-case input like "Chunky-Trailer" to "chunky-trailer".
        let encoder = Encoder::chunked();
        let trailers = vec![HeaderName::from_static("chunky-trailer")];
        let encoder = encoder.into_chunked_with_trailing_fields(trailers);

        // The actual trailer being sent
        let headers = HeaderMap::from_iter(vec![(
            HeaderName::from_static("chunky-trailer"),
            HeaderValue::from_static("trailer value"),
        )]);

        let buf = encoder
            .encode_trailers::<&[u8]>(headers, false, false)
            .unwrap();
        let mut dst = Vec::new();
        dst.put(buf);
        assert_eq!(dst, b"0\r\nchunky-trailer: trailer value\r\n\r\n");
    }
}
