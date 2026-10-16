//! Extensions for HTTP messages in Hyper.
//!
//! This module provides types and utilities that extend the capabilities of HTTP requests and responses
//! in Hyper. Extensions are additional pieces of information or features that can be attached to HTTP
//! messages via the [`http::Extensions`] map, which is
//! accessible through methods like [`http::Request::extensions`] and [`http::Response::extensions`].
//!
//! # What are extensions?
//!
//! Extensions allow Hyper to associate extra metadata or behaviors with HTTP messages, beyond the standard
//! headers and body. These can be used by advanced users and library authors to access protocol-specific
//! features, track original header casing, handle informational responses, and more.
//!
//! # How to access extensions
//!
//! Extensions are stored in the `Extensions` map of a request or response. You can access them using:
//!
//! ```rust
//! # let response = http::Response::new(());
//! if let Some(ext) = response.extensions().get::<hyper::ext::ReasonPhrase>() {
//!     // use the extension
//! }
//! ```
//!
//! # Extension Groups
//!
//! The extensions in this module can be grouped as follows:
//!
//! - **HTTP/1 Reason Phrase**: [`ReasonPhrase`] — Access non-canonical reason phrases in HTTP/1 responses.
//! - **Informational Responses**: [`on_informational`] — Register callbacks for 1xx HTTP/1 responses on the client.
//! - **Header Case Tracking**: Internal types for tracking the original casing and order of headers as received.
//! - **HTTP/2 Protocol Extensions**: [`Protocol`] — Access the `:protocol` pseudo-header for Extended CONNECT in HTTP/2.
//!
//! Some extensions are only available for specific protocols (HTTP/1 or HTTP/2) or use cases (client, server, FFI).
//!
//! See the documentation on each item for details about its usage and requirements.

#[cfg(all(
    any(feature = "client", feature = "server"),
    any(feature = "http1", feature = "http2")
))]
use bytes::Bytes;
#[cfg(any(
    all(any(feature = "client", feature = "server"), feature = "http1"),
    feature = "ffi"
))]
use http::header::HeaderName;
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
use http::header::{HeaderMap, HeaderValue, IntoHeaderName, ValueIter};
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
use std::collections::HashMap;
#[cfg(any(feature = "http2", all(feature = "client", feature = "http1")))]
use std::fmt;
#[cfg(all(
    any(feature = "client", feature = "server"),
    any(feature = "http1", feature = "http2")
))]
use std::sync::{Arc, OnceLock};

#[cfg(any(feature = "http1", feature = "ffi"))]
mod h1_reason_phrase;
#[cfg(any(feature = "http1", feature = "ffi"))]
pub use h1_reason_phrase::ReasonPhrase;

#[cfg(all(feature = "http1", feature = "client"))]
mod informational;
#[cfg(all(feature = "http1", feature = "client"))]
pub use informational::on_informational;
#[cfg(all(feature = "http1", feature = "client"))]
pub(crate) use informational::OnInformational;
#[cfg(all(feature = "http1", feature = "client", feature = "ffi"))]
pub(crate) use informational::{on_informational_raw, OnInformationalCallback};

#[cfg(feature = "http2")]
/// Extension type representing the `:protocol` pseudo-header in HTTP/2.
///
/// The `Protocol` extension allows access to the value of the `:protocol` pseudo-header
/// used by the [Extended CONNECT Protocol](https://datatracker.ietf.org/doc/html/rfc8441#section-4).
/// This extension is only sent on HTTP/2 CONNECT requests, most commonly with the value `websocket`.
///
/// # Example
///
/// ```rust
/// use hyper::ext::Protocol;
/// use http::{Request, Method, Version};
///
/// let mut req = Request::new(());
/// *req.method_mut() = Method::CONNECT;
/// *req.version_mut() = Version::HTTP_2;
/// req.extensions_mut().insert(Protocol::from_static("websocket"));
/// // Now the request will include the `:protocol` pseudo-header with value "websocket"
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    inner: h2::ext::Protocol,
}

#[cfg(feature = "http2")]
impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            inner: h2::ext::Protocol::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    #[cfg(feature = "server")]
    pub(crate) fn from_inner(inner: h2::ext::Protocol) -> Self {
        Self { inner }
    }

    #[cfg(all(feature = "client", feature = "http2"))]
    pub(crate) fn into_inner(self) -> h2::ext::Protocol {
        self.inner
    }
}

#[cfg(feature = "http2")]
impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            inner: h2::ext::Protocol::from(value),
        }
    }
}

#[cfg(feature = "http2")]
impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

#[cfg(feature = "http2")]
impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// How HTTP/2 clients sent their frames, as a server built with
/// [`record_frames`](crate::server::conn::http2::Builder::record_frames) records them.
#[cfg(all(feature = "http2", feature = "server"))]
pub mod http2 {
    pub use h2::ext::{
        deferred_preface, DeferredPreface, FrameLog, HeadersFrame, LoggedFrame, PrefaceFrame,
        PrefaceSender, PseudoHeader, RelayedEnd, StreamPriority,
    };
}

/// A map from header names to their original casing as received in an HTTP message.
///
/// If an HTTP/1 response `res` is parsed on a connection whose option
/// [`preserve_header_case`] was set to true and the response included
/// the following headers:
///
/// ```ignore
/// x-Bread: Baguette
/// X-BREAD: Pain
/// x-bread: Ficelle
/// ```
///
/// Then `res.extensions().get::<HeaderCaseMap>()` will return a map with:
///
/// ```ignore
/// HeaderCaseMap({
///     "x-bread": ["x-Bread", "X-BREAD", "x-bread"],
/// })
/// ```
///
/// A request a server parses with `preserve_header_case` also records the colon and
/// whitespace around each field's value, which the HTTP/1 encoders write back around that
/// field's value (whatever the value now is); a field without a record gets `": "`.
///
/// [`preserve_header_case`]: /client/struct.Client.html#method.preserve_header_case
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Clone, Debug)]
pub struct HeaderCaseMap(HeaderMap<Bytes>, HeaderMap<FieldSpacing>);

/// What a parsed field line had between its name and its value (the colon and the
/// whitespace around it), and the whitespace after its value.
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Clone, Debug)]
pub struct FieldSpacing {
    /// The colon and the whitespace around it.
    pub separator: Bytes,
    /// The whitespace after the value.
    pub trailing: Bytes,
}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl HeaderCaseMap {
    /// Returns a view of all spellings associated with that header name,
    /// in the order they were found.
    pub fn get_all<'a>(&'a self, name: &HeaderName) -> impl Iterator<Item = &'a Bytes> + 'a {
        self.get_all_internal(name)
    }

    /// Returns a view of all spellings associated with that header name,
    /// in the order they were found.
    #[cfg(any(feature = "client", feature = "server"))]
    pub(crate) fn get_all_internal(&self, name: &HeaderName) -> ValueIter<'_, Bytes> {
        self.0.get_all(name).into_iter()
    }

    /// An empty map, for messages whose original spelling is known to the caller
    /// (a proxy relaying a response received over another transport).
    pub fn new() -> Self {
        Self(HeaderMap::default(), HeaderMap::default())
    }

    #[cfg(any(feature = "client", feature = "server"))]
    pub(crate) fn default() -> Self {
        Self::new()
    }

    #[cfg(any(test, feature = "ffi"))]
    pub(crate) fn insert(&mut self, name: HeaderName, orig: Bytes) {
        self.0.insert(name, orig);
    }

    /// Records another spelling of `name`, in order of appearance.
    ///
    /// # Errors
    ///
    /// Fails, recording nothing, unless `orig` is `name` in some ASCII case, as the
    /// HTTP/1 encoders write it in place of `name`.
    pub fn append<N>(&mut self, name: N, orig: Bytes) -> Result<(), InvalidHeaderSpelling>
    where
        N: IntoHeaderName + AsRef<str>,
    {
        if !orig.eq_ignore_ascii_case(name.as_ref().as_bytes()) {
            return Err(InvalidHeaderSpelling(()));
        }
        self.0.append(name, orig);
        Ok(())
    }

    /// Records another spelling of `name`, which `orig` was parsed into.
    pub(crate) fn append_parsed(&mut self, name: &HeaderName, orig: Bytes) {
        self.0.append(name, orig);
    }

    /// Records another spelling of `name` and what surrounds its value.
    pub(crate) fn append_spaced(&mut self, name: &HeaderName, orig: Bytes, spacing: FieldSpacing) {
        self.0.append(name, orig);
        self.1.append(name, spacing);
    }

    /// What surrounds the `nth` value of `name`, when recorded.
    pub fn spacing(&self, name: &HeaderName, nth: usize) -> Option<&FieldSpacing> {
        self.1.get_all(name).iter().nth(nth)
    }
}

/// The error [`HeaderCaseMap::append`] returns for a spelling of another header name.
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Debug)]
pub struct InvalidHeaderSpelling(());

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl std::fmt::Display for InvalidHeaderSpelling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("spelling is not of its header name")
    }
}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl std::error::Error for InvalidHeaderSpelling {}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl Default for HeaderCaseMap {
    fn default() -> Self {
        Self::new()
    }
}

/// The order in which headers were received, including repeated names.
///
/// Recorded alongside [`HeaderCaseMap`] when `preserve_header_case` is enabled
/// and stored as an extension on the parsed message; the encoders write headers
/// back in this order. Each entry is a header name plus the index of that value
/// among the values of the same name.
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Clone, Debug)]
pub struct OriginalHeaderOrder {
    /// Stores how many entries a Headername maps to. This is used
    /// for accounting.
    num_entries: HashMap<HeaderName, usize>,
    /// Stores the ordering of the headers. ex: `vec[i] = (headerName, idx)`,
    /// The vector is ordered such that the ith element
    /// represents the ith header that came in off the line.
    /// The `HeaderName` and `idx` are then used elsewhere to index into
    /// the multi map that stores the header values.
    entry_order: Vec<(HeaderName, usize)>,
}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl OriginalHeaderOrder {
    /// An empty order, for messages whose original order is known to the caller.
    pub fn new() -> Self {
        OriginalHeaderOrder {
            num_entries: HashMap::new(),
            entry_order: Vec::new(),
        }
    }

    pub(crate) fn default() -> Self {
        Self::new()
    }

    #[cfg(feature = "ffi")]
    pub(crate) fn insert(&mut self, name: HeaderName) {
        if !self.num_entries.contains_key(&name) {
            let idx = 0;
            self.num_entries.insert(name.clone(), 1);
            self.entry_order.push((name, idx));
        }
        // Replacing an already existing element does not
        // change ordering, so we only care if its the first
        // header name encountered
    }

    /// Records the next header as `name`, in order of appearance.
    pub fn append<N>(&mut self, name: N)
    where
        N: IntoHeaderName + Into<HeaderName> + Clone,
    {
        let name: HeaderName = name.into();
        let idx = match self.num_entries.entry(name.clone()) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let idx = *entry.get();
                *entry.get_mut() += 1;
                idx
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(1);
                0
            }
        };
        self.entry_order.push((name, idx));
    }

    /// Header names, each paired with its index among the values of that name,
    /// in the order they were originally received.
    ///
    /// # Examples
    /// ```
    /// use hyper::ext::OriginalHeaderOrder;
    /// use hyper::header::{HeaderMap, HeaderName, HeaderValue};
    ///
    /// let mut order = OriginalHeaderOrder::new();
    /// let mut map = HeaderMap::new();
    /// for (name, value) in [
    ///     ("set-cookie", "a=b"),
    ///     ("content-encoding", "gzip"),
    ///     ("set-cookie", "c=d"),
    /// ] {
    ///     let name = HeaderName::from_static(name);
    ///     map.append(name.clone(), HeaderValue::from_static(value));
    ///     order.append(name);
    /// }
    ///
    /// let wire: Vec<(&str, usize)> = order
    ///     .get_in_order()
    ///     .map(|(name, index)| (name.as_str(), *index))
    ///     .collect();
    /// assert_eq!(
    ///     wire,
    ///     [("set-cookie", 0), ("content-encoding", 0), ("set-cookie", 1)]
    /// );
    /// assert_eq!(map.get_all("set-cookie").iter().nth(1).unwrap(), "c=d");
    /// ```
    pub fn get_in_order(&self) -> impl Iterator<Item = &(HeaderName, usize)> {
        self.entry_order.iter()
    }

    /// `headers`' values in the recorded order: `(name, n, value)` where `value`
    /// is the `n`-th value of `name`. Values the recorded order doesn't cover
    /// (headers added after parsing) follow in map order; recorded entries whose
    /// header was removed are skipped.
    pub fn entries(&self, headers: &HeaderMap) -> Vec<(HeaderName, usize, HeaderValue)> {
        let mut slots: HashMap<&HeaderName, Vec<Option<&HeaderValue>>> = HashMap::new();
        for name in headers.keys() {
            slots.insert(name, headers.get_all(name).iter().map(Some).collect());
        }
        let mut out = Vec::with_capacity(headers.len());
        for (name, nth) in self.get_in_order() {
            if let Some(value) = slots.get_mut(name).and_then(|values| values.get_mut(*nth)) {
                if let Some(value) = value.take() {
                    out.push((name.clone(), *nth, value.clone()));
                }
            }
        }
        for name in headers.keys() {
            if let Some(values) = slots.get_mut(name) {
                for (nth, value) in values.iter_mut().enumerate() {
                    if let Some(value) = value.take() {
                        out.push((name.clone(), nth, value.clone()));
                    }
                }
            }
        }
        out
    }
}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl Default for OriginalHeaderOrder {
    fn default() -> Self {
        Self::new()
    }
}

/// A message's trailer fields in the order received, each name spelled as sent (lowercase
/// over HTTP/2), which the trailers `HeaderMap` its body yields lowercases and groups.
///
/// hyper inserts one into each chunked HTTP/1 message it reads with
/// `preserve_header_case`, and the HTTP/2 server into each request with a body, and fills
/// it as it reads the trailers, before the body yields them. An HTTP/1 message hyper writes, or a
/// response the HTTP/2 server sends, carrying a filled one sends its trailers in that
/// spelling and order. Clones share the fields, so a proxy can hand a received message's
/// record (or its cell, to another HTTP library) to the message it relays before the
/// trailers arrive.
#[cfg(all(
    any(feature = "client", feature = "server"),
    any(feature = "http1", feature = "http2")
))]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawTrailers(pub Arc<OnceLock<Vec<(Bytes, http::HeaderValue)>>>);

/// What each of an HTTP/1 message's trailer fields had between its name and its value
/// (the colon included), and after its value up to its line ending, in the order of its
/// [`RawTrailers`].
///
/// hyper inserts one next to each `RawTrailers` it inserts into an HTTP/1 message and
/// fills it as it reads the trailers. An HTTP/1 message hyper writes carrying a filled one
/// with its `RawTrailers` writes its trailers so. Clones share the record, like
/// `RawTrailers`.
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrailerSpacing(pub Arc<OnceLock<Vec<(Bytes, Bytes)>>>);

/// A chunked HTTP/1 body's chunk-size lines as received, in order: each chunk's size and
/// its line as sent (the size digits' spelling, any whitespace, and the chunk
/// extensions, without the CRLF), the last chunk (size 0) included.
///
/// hyper inserts one into each chunked request a server connection built with
/// [`preserve_chunks`](crate::server::conn::http1::Builder::preserve_chunks) reads, and
/// into the chunked response to a client request marked with
/// [`record_response_chunks`], and appends each line as it reads it, before the chunk's
/// data. A chunked HTTP/1 message hyper writes carrying one splits its body at the
/// recorded sizes and writes each recorded line, whatever frames the body yields, so a
/// proxy relaying a received body keeps its chunks and their extensions; bytes past the
/// record go out one chunk per frame, and a body ending inside a recorded chunk is an
/// error. It drops each line from the record once written, so a long body's record holds
/// only the lines still to go out (the last chunk's stays). A body whose record holds 4096 lines
/// not yet written fails. Clones share the lines, so a
/// proxy can hand a received message's record (or its cell, to another HTTP library) to
/// the message it relays as the lines arrive; one also reading them takes them from the
/// received record as they arrive, handing them on to a record of its own that the
/// relayed message carries.
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Clone, Debug, Default)]
pub struct RawChunks(pub Arc<std::sync::Mutex<Vec<(u64, Bytes)>>>);

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl RawChunks {
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Vec<(u64, Bytes)>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl PartialEq for RawChunks {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// The path and query of a request-target received with raw non-ASCII bytes, as sent
/// (`raw`) and as its `Uri` carries them percent-encoded (`encoded`). hyper inserts one
/// into each such request a server parses; an HTTP/1 client writes `raw` for a request
/// carrying one whose `Uri`'s path and query are still `encoded`.
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Clone, Debug)]
pub struct RawRequestTarget {
    /// The path and query as sent.
    pub raw: Bytes,
    /// The path and query as the request's `Uri` carries them.
    pub encoded: http::uri::PathAndQuery,
}

/// Relays an HTTP/1 client's half-close. hyper inserts one into each request a server
/// connection built with [`half_close`](crate::server::conn::http1::Builder::half_close)
/// reads, and marks it when the client ends its sending side mid-message. An HTTP/1
/// client connection writing a request carrying one ends its own sending side once it
/// has written the request and the mark is set, as the client did.
#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Clone, Debug, Default)]
pub struct ReadClosed(Arc<ReadClosedMark>);

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
#[derive(Debug, Default)]
struct ReadClosedMark {
    closed: std::sync::atomic::AtomicBool,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

#[cfg(all(any(feature = "client", feature = "server"), feature = "http1"))]
impl ReadClosed {
    #[cfg(feature = "server")]
    pub(crate) fn close(&self) {
        self.0
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        let waker = self
            .0
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Ready once the client ended its sending side; otherwise wakes `cx` when it does.
    pub fn poll_closed(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let closed = || self.0.closed.load(std::sync::atomic::Ordering::Acquire);
        if !closed() {
            *self
                .0
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cx.waker().clone());
            if !closed() {
                return std::task::Poll::Pending;
            }
        }
        std::task::Poll::Ready(())
    }
}

/// An HTTP/2 request's stream ending in a reset before its response: hyper inserts one
/// into each request a server connection built with
/// [`serve_reset_requests`](crate::server::conn::http2::Builder::serve_reset_requests)
/// hands over, and marks it with the reset's error code when the stream is reset (by its
/// client, or refused under a relayed `GOAWAY`) while the service runs on, its response
/// then going nowhere.
#[cfg(all(feature = "http2", feature = "server"))]
#[derive(Clone, Debug, Default)]
pub struct StreamReset(Arc<StreamResetMark>);

#[cfg(all(feature = "http2", feature = "server"))]
#[derive(Debug, Default)]
struct StreamResetMark {
    code: std::sync::OnceLock<u32>,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

#[cfg(all(feature = "http2", feature = "server"))]
impl StreamReset {
    pub(crate) fn reset(&self, code: u32) {
        let _ = self.0.code.set(code);
        let waker = self
            .0
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The reset's error code once the stream was reset; otherwise wakes `cx` when it is.
    pub fn poll_reset(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<u32> {
        if let Some(code) = self.0.code.get() {
            return std::task::Poll::Ready(*code);
        }
        *self
            .0
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cx.waker().clone());
        match self.0.code.get() {
            Some(code) => std::task::Poll::Ready(*code),
            None => std::task::Poll::Pending,
        }
    }
}

/// Marks a client request whose chunked response should carry a [`RawChunks`] record.
#[cfg(all(feature = "client", feature = "http1"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecordResponseChunks;

/// Asks an HTTP/1 client connection to record the chunk-size lines of the response to
/// `req` in a [`RawChunks`] extension on the response, if it is chunked.
#[cfg(all(feature = "client", feature = "http1"))]
pub fn record_response_chunks<B>(req: &mut http::Request<B>) {
    req.extensions_mut().insert(RecordResponseChunks);
}

/// Makes an HTTP/1 client connection honour the `Expect: 100-continue` of the request
/// carrying it: the connection writes the head, then holds the body back until the
/// server answers `100 Continue` (passed to [`on_informational`] like any interim
/// response) or `timeout` passes. A final response arriving first means the body is
/// never sent, and the connection closes after that response.
///
/// Without this extension, or on a request without `Expect: 100-continue`, an empty
/// body, or HTTP/1.0, the body follows the head at once.
#[cfg(all(feature = "client", feature = "http1"))]
#[derive(Clone)]
pub struct ExpectContinue {
    pub(crate) wait: Option<(Arc<dyn crate::rt::Timer + Send + Sync>, std::time::Duration)>,
}

#[cfg(all(feature = "client", feature = "http1"))]
impl ExpectContinue {
    /// Waits for `100 Continue` up to `timeout`, measured by `timer` from when the head is
    /// written (curl waits 1 second).
    pub fn new<T>(timer: T, timeout: std::time::Duration) -> Self
    where
        T: crate::rt::Timer + Send + Sync + 'static,
    {
        Self {
            wait: Some((Arc::new(timer), timeout)),
        }
    }

    /// Sends the body as soon as it yields data, for a body whose producer already waits
    /// for `100 Continue` (a proxy relaying its client's body). A final response arriving
    /// before any of the body was written still closes the connection after it.
    pub fn relayed() -> Self {
        Self { wait: None }
    }
}

#[cfg(all(feature = "client", feature = "http1"))]
impl fmt::Debug for ExpectContinue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpectContinue")
            .field("timeout", &self.wait.as_ref().map(|(_, timeout)| timeout))
            .finish()
    }
}

/// Sends interim (1xx) response heads to the client ahead of the service's final
/// response, on an HTTP/1 or HTTP/2 connection built with `informational_responses`
/// ([HTTP/1](crate::server::conn::http1::Builder::informational_responses),
/// [HTTP/2](crate::server::conn::http2::Builder::informational_responses)).
///
/// hyper inserts one into each request's extensions. Every [`send`](Self::send)
/// writes the head (`HTTP/1.1 <status> <reason>` plus the given headers, or an
/// HTTP/2 HEADERS frame) to the client as soon as the connection can write. Sends
/// after the final response head has been written are dropped. An HTTP/1 connection
/// takes heads only while its write buffer has room, the rest staying queued, and a
/// sender queues at most 16 heads not yet taken.
#[cfg(all(any(feature = "http1", feature = "http2"), feature = "server"))]
#[derive(Clone, Debug)]
pub struct InformationalSender {
    tx: tokio::sync::mpsc::Sender<http::Response<()>>,
}

#[cfg(all(any(feature = "http1", feature = "http2"), feature = "server"))]
impl InformationalSender {
    /// Queues an interim head.
    ///
    /// # Errors
    ///
    /// Returns the response back when its status is not 1xx, is 101 Switching Protocols,
    /// when the connection no longer accepts interim heads, or when 16 are already queued.
    pub fn send(&self, res: http::Response<()>) -> Result<(), http::Response<()>> {
        if !res.status().is_informational() || res.status() == http::StatusCode::SWITCHING_PROTOCOLS
        {
            return Err(res);
        }
        self.tx.try_send(res).map_err(|err| match err {
            tokio::sync::mpsc::error::TrySendError::Full(res)
            | tokio::sync::mpsc::error::TrySendError::Closed(res) => res,
        })
    }
}

#[cfg(all(any(feature = "http1", feature = "http2"), feature = "server"))]
pub(crate) struct InformationalReceiver {
    rx: tokio::sync::mpsc::Receiver<http::Response<()>>,
}

#[cfg(all(any(feature = "http1", feature = "http2"), feature = "server"))]
impl InformationalReceiver {
    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<http::Response<()>>> {
        self.rx.poll_recv(cx)
    }
}

#[cfg(all(any(feature = "http1", feature = "http2"), feature = "server"))]
pub(crate) fn informational_channel() -> (InformationalSender, InformationalReceiver) {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    (InformationalSender { tx }, InformationalReceiver { rx })
}

/// The pushes, as they come, an HTTP/2 server promises (RFC 9113 §8.4) on the stream of the
/// response whose extensions carry them.
#[cfg(all(feature = "http2", feature = "server"))]
pub(crate) type Http2PushStream<B> =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = Http2Push<B>> + Send>>;

/// HTTP/2 server pushes (RFC 9113 §8.4) to promise on the stream of the response whose
/// extensions carry them. hyper promises each as it comes while that stream is open, and
/// sends its response from a task of its own; the stream ends only once the pushes have,
/// so that every promise precedes its end. A push the client can't take (it disabled push)
/// is dropped.
#[cfg(all(feature = "http2", feature = "server"))]
pub struct Http2Pushes<B>(Arc<std::sync::Mutex<Option<Http2PushStream<B>>>>);

#[cfg(all(feature = "http2", feature = "server"))]
impl<B> Http2Pushes<B> {
    /// The pushes `pushes` yields.
    pub fn new(pushes: impl futures_core::Stream<Item = Http2Push<B>> + Send + 'static) -> Self {
        Self(Arc::new(std::sync::Mutex::new(Some(Box::pin(pushes)))))
    }

    pub(crate) fn take(&self) -> Option<Http2PushStream<B>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

#[cfg(all(feature = "http2", feature = "server"))]
impl<B> Clone for Http2Pushes<B> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

#[cfg(all(feature = "http2", feature = "server"))]
impl<B> fmt::Debug for Http2Pushes<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2Pushes").finish_non_exhaustive()
    }
}

/// A push to promise (see [`Http2Pushes`]).
#[cfg(all(feature = "http2", feature = "server"))]
pub struct Http2Push<B> {
    /// The promised request's head.
    pub request: http::Request<()>,
    /// Its response; an error resets the pushed stream, and the client resetting it drops
    /// the response.
    pub response: std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<http::Response<B>, Box<dyn std::error::Error + Send + Sync>>,
                > + Send,
        >,
    >,
}

#[cfg(all(feature = "http2", feature = "server"))]
impl<B> fmt::Debug for Http2Push<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2Push")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}
