use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use atomic_waker::AtomicWaker;
use bytes::{Buf, Bytes};
use futures_core::ready;
use h2::server::{Connection, Handshake, SendPushedResponse, SendResponse};
use h2::{Reason, RecvStream};
use http::{Method, Request};
use pin_project_lite::pin_project;

use super::{ping, PipeToSendStream, SendBuf};
use crate::body::{Body, Incoming as IncomingBody};
use crate::common::date;
use crate::common::io::Compat;
use crate::common::time::Time;
#[cfg(feature = "http1")]
use crate::ext::OriginalHeaderOrder;
use crate::ext::{Http2PushStream, Http2Pushes, InformationalReceiver, Protocol, RawTrailers};
use crate::headers;
use crate::proto::h2::ping::Recorder;
use crate::proto::Dispatched;
use crate::rt::bounds::{Http2PushExec, Http2ServerConnExec, Http2UpgradedExec};
use crate::rt::{Read, Write};
use crate::service::HttpService;

use crate::upgrade::{OnUpgrade, Pending, Upgraded};
use crate::Response;

// Our defaults are chosen for the "majority" case, which usually are not
// resource constrained, and so the spec default of 64kb can be too limiting
// for performance.
//
// At the same time, a server more often has multiple clients connected, and
// so is more likely to use more resources than a client would.
const DEFAULT_CONN_WINDOW: u32 = 1024 * 1024; // 1mb
const DEFAULT_STREAM_WINDOW: u32 = 1024 * 1024; // 1mb
const DEFAULT_MAX_FRAME_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_SEND_BUF_SIZE: usize = 1024 * 400; // 400kb
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_LOCAL_ERROR_RESET_STREAMS: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) adaptive_window: bool,
    pub(crate) initial_conn_window_size: u32,
    pub(crate) initial_stream_window_size: u32,
    pub(crate) max_frame_size: u32,
    pub(crate) enable_connect_protocol: bool,
    pub(crate) max_concurrent_streams: Option<u32>,
    pub(crate) max_pending_accept_reset_streams: Option<usize>,
    pub(crate) max_local_error_reset_streams: Option<usize>,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) keep_alive_timeout: Duration,
    pub(crate) max_send_buffer_size: usize,
    pub(crate) header_table_size: Option<u32>,
    pub(crate) max_header_list_size: u32,
    pub(crate) date_header: bool,
    pub(crate) informational: bool,
    pub(crate) extended_connect_as_request: bool,
    pub(crate) record_frames: Option<usize>,
    pub(crate) deferred_preface: Option<h2::ext::DeferredPreface>,
    pub(crate) leave_close_to_client: bool,
    pub(crate) relayed_end: Option<h2::ext::RelayedEnd>,
    pub(crate) serve_reset_requests: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            adaptive_window: false,
            initial_conn_window_size: DEFAULT_CONN_WINDOW,
            initial_stream_window_size: DEFAULT_STREAM_WINDOW,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            enable_connect_protocol: false,
            max_concurrent_streams: Some(200),
            max_pending_accept_reset_streams: None,
            max_local_error_reset_streams: Some(DEFAULT_MAX_LOCAL_ERROR_RESET_STREAMS),
            header_table_size: None,
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            max_send_buffer_size: DEFAULT_MAX_SEND_BUF_SIZE,
            max_header_list_size: DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE,
            date_header: true,
            informational: false,
            extended_connect_as_request: false,
            record_frames: None,
            deferred_preface: None,
            leave_close_to_client: false,
            relayed_end: None,
            serve_reset_requests: false,
        }
    }
}

pin_project! {
    pub(crate) struct Server<T, S, B, E>
    where
        S: HttpService<IncomingBody>,
        B: Body,
    {
        exec: E,
        timer: Time,
        service: S,
        state: State<T, B>,
        date_header: bool,
        informational: bool,
        extended_connect_as_request: bool,
        close_pending: bool,
        reset_requests: Option<ResetRequests>,
    }
}

//#[expect(clippy::large_enum_variant, reason = "the whole future is boxed")]
#[allow(clippy::large_enum_variant)]
enum State<T, B>
where
    B: Body,
{
    Handshaking {
        ping_config: ping::Config,
        hs: Handshake<Compat<T>, SendBuf<B::Data>>,
    },
    Serving(Serving<T, B>),
}

struct Serving<T, B>
where
    B: Body,
{
    ping: Option<(ping::Recorder, ping::Ponger)>,
    conn: Connection<Compat<T>, SendBuf<B::Data>>,
    closing: Option<crate::Error>,
    date_header: bool,
    informational: bool,
    extended_connect_as_request: bool,
    reset_requests: Option<ResetRequests>,
}

/// The requests a connection serves on after their clients reset their streams (see
/// `Config::serve_reset_requests`): how many run, `max` at most.
#[derive(Clone)]
struct ResetRequests {
    running: Arc<AtomicUsize>,
    max: usize,
}

impl ResetRequests {
    /// A place for one more, unless `max` run.
    fn take(&self) -> Option<ResetRequest> {
        let request = ResetRequest(Arc::clone(&self.running));
        (self.running.fetch_add(1, Ordering::AcqRel) < self.max).then_some(request)
    }
}

/// A request served on after its client reset its stream, until dropped.
struct ResetRequest(Arc<AtomicUsize>);

impl Drop for ResetRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<T, S, B, E> Server<T, S, B, E>
where
    T: Read + Write + Unpin,
    S: HttpService<IncomingBody, ResBody = B>,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    B: Body + 'static,
    E: Http2ServerConnExec<S::Future, B>,
{
    pub(crate) fn new(
        io: T,
        service: S,
        config: &Config,
        exec: E,
        timer: Time,
    ) -> Server<T, S, B, E> {
        let mut builder = h2::server::Builder::default();
        builder
            .initial_window_size(config.initial_stream_window_size)
            .initial_connection_window_size(config.initial_conn_window_size)
            .max_frame_size(config.max_frame_size)
            .max_header_list_size(config.max_header_list_size)
            .max_local_error_reset_streams(config.max_local_error_reset_streams)
            .max_send_buffer_size(config.max_send_buffer_size);
        if let Some(max) = config.max_concurrent_streams {
            builder.max_concurrent_streams(max);
        }
        if let Some(max) = config.max_pending_accept_reset_streams {
            builder.max_pending_accept_reset_streams(max);
        }
        if let Some(size) = config.header_table_size {
            builder.header_table_size(size);
        }
        if config.enable_connect_protocol {
            builder.enable_connect_protocol();
        }
        if let Some(limit) = config.record_frames {
            builder.record_frames(limit);
        }
        if let Some(preface) = config.deferred_preface.clone() {
            builder.deferred_preface(preface);
        }
        if config.leave_close_to_client {
            builder.leave_close_to_client();
        }
        if let Some(end) = config.relayed_end.clone() {
            builder.relayed_end(end);
        }
        let handshake = builder.handshake(Compat::new(io));

        let bdp = if config.adaptive_window {
            Some(config.initial_stream_window_size)
        } else {
            None
        };

        let ping_config = ping::Config {
            bdp_initial_window: bdp,
            keep_alive_interval: config.keep_alive_interval,
            keep_alive_timeout: config.keep_alive_timeout,
            // If keep-alive is enabled for servers, always enabled while
            // idle, so it can more aggressively close dead connections.
            keep_alive_while_idle: true,
        };

        Server {
            exec,
            timer,
            state: State::Handshaking {
                ping_config,
                hs: handshake,
            },
            service,
            date_header: config.date_header,
            informational: config.informational,
            extended_connect_as_request: config.extended_connect_as_request,
            close_pending: false,
            reset_requests: config.serve_reset_requests.then(|| ResetRequests {
                running: Arc::new(AtomicUsize::new(0)),
                max: config
                    .max_concurrent_streams
                    .map_or(usize::MAX, |max| max as usize),
            }),
        }
    }

    pub(crate) fn graceful_shutdown(&mut self) {
        trace!("graceful_shutdown");
        match &mut self.state {
            State::Handshaking { .. } => {
                self.close_pending = true;
            }
            State::Serving(srv) => {
                if srv.closing.is_none() {
                    srv.conn.graceful_shutdown();
                }
            }
        }
    }
}

impl<T, S, B, E> Future for Server<T, S, B, E>
where
    T: Read + Write + Unpin,
    S: HttpService<IncomingBody, ResBody = B>,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    B: Body + 'static,
    E: Http2ServerConnExec<S::Future, B>,
{
    type Output = crate::Result<Dispatched>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = &mut *self;
        loop {
            let next = match &mut me.state {
                State::Handshaking { hs, ping_config } => {
                    let mut conn = ready!(Pin::new(hs).poll(cx).map_err(crate::Error::new_h2))?;
                    let ping = if ping_config.is_enabled() {
                        let pp = conn.ping_pong().expect("conn.ping_pong");
                        Some(ping::channel(pp, ping_config.clone(), me.timer.clone()))
                    } else {
                        None
                    };
                    State::Serving(Serving {
                        ping,
                        conn,
                        closing: None,
                        date_header: me.date_header,
                        informational: me.informational,
                        extended_connect_as_request: me.extended_connect_as_request,
                        reset_requests: me.reset_requests.clone(),
                    })
                }
                State::Serving(srv) => {
                    // graceful_shutdown was called before handshaking finished,
                    if me.close_pending && srv.closing.is_none() {
                        srv.conn.graceful_shutdown();
                    }
                    ready!(srv.poll_server(cx, &mut me.service, &mut me.exec))?;
                    return Poll::Ready(Ok(Dispatched::Shutdown));
                }
            };
            me.state = next;
        }
    }
}

impl<T, B> Serving<T, B>
where
    T: Read + Write + Unpin,
    B: Body + 'static,
{
    fn poll_server<S, E>(
        &mut self,
        cx: &mut Context<'_>,
        service: &mut S,
        exec: &mut E,
    ) -> Poll<crate::Result<()>>
    where
        S: HttpService<IncomingBody, ResBody = B>,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        E: Http2ServerConnExec<S::Future, B>,
    {
        if self.closing.is_none() {
            loop {
                self.poll_ping(cx);

                match ready!(self.conn.poll_accept(cx)) {
                    Some(Ok((req, mut respond))) => {
                        trace!("incoming request");
                        let content_length = headers::content_length_parse_all(req.headers());
                        let ping = self
                            .ping
                            .as_ref()
                            .map(|ping| ping.0.clone())
                            .unwrap_or_else(ping::disabled);

                        // Record the headers received
                        ping.record_non_data();

                        let is_connect = req.method() == Method::CONNECT
                            && !(self.extended_connect_as_request
                                && req.extensions().get::<h2::ext::Protocol>().is_some());
                        let (mut parts, stream) = req.into_parts();
                        let (mut req, connect_parts) = if !is_connect {
                            // Trailers may follow a body; record their field order.
                            let raw_trailers = (!stream.is_end_stream()).then(|| {
                                let raw = RawTrailers::default();
                                parts.extensions.insert(raw.clone());
                                raw
                            });
                            (
                                Request::from_parts(
                                    parts,
                                    IncomingBody::h2(
                                        stream,
                                        content_length.into(),
                                        ping,
                                        raw_trailers,
                                    ),
                                ),
                                None,
                            )
                        } else {
                            if content_length.map_or(false, |len| len != 0) {
                                warn!("h2 connect request with non-zero body not supported");
                                respond.send_reset(h2::Reason::INTERNAL_ERROR);
                                continue;
                            }
                            let (pending, upgrade) = crate::upgrade::pending();
                            debug_assert!(parts.extensions.get::<OnUpgrade>().is_none());
                            parts.extensions.insert(upgrade);
                            (
                                Request::from_parts(parts, IncomingBody::empty()),
                                Some(ConnectParts {
                                    pending,
                                    ping,
                                    recv_stream: stream,
                                }),
                            )
                        };

                        if let Some(protocol) = req.extensions_mut().remove::<h2::ext::Protocol>() {
                            req.extensions_mut().insert(Protocol::from_inner(protocol));
                        }
                        #[cfg(feature = "http1")]
                        record_header_order(req.extensions_mut());

                        let informational = self.informational.then(|| {
                            let (tx, rx) = crate::ext::informational_channel();
                            req.extensions_mut().insert(tx);
                            rx
                        });
                        let stream_reset = self.reset_requests.is_some().then(|| {
                            let reset = crate::ext::StreamReset::default();
                            req.extensions_mut().insert(reset.clone());
                            reset
                        });

                        let fut = H2Stream::new(
                            service.call(req),
                            connect_parts,
                            respond,
                            self.date_header,
                            informational,
                            exec.clone(),
                            self.reset_requests.clone(),
                            stream_reset,
                        );

                        exec.execute_h2stream(fut);
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(Err(crate::Error::new_h2(e)));
                    }
                    None => {
                        // no more incoming streams...
                        if let Some((ping, _)) = &self.ping {
                            ping.ensure_not_timed_out()?;
                        }

                        trace!("incoming connection complete");
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }

        debug_assert!(
            self.closing.is_some(),
            "poll_server broke loop without closing"
        );

        ready!(self.conn.poll_closed(cx).map_err(crate::Error::new_h2))?;

        Poll::Ready(Err(self.closing.take().expect("polled after error")))
    }

    fn poll_ping(&mut self, cx: &mut Context<'_>) {
        if let Some((_, estimator)) = &mut self.ping {
            match estimator.poll(cx) {
                Poll::Ready(ping::Ponged::SizeUpdate(wnd)) => {
                    self.conn.set_target_window_size(wnd);
                    let _ = self.conn.set_initial_window_size(wnd);
                }
                Poll::Ready(ping::Ponged::KeepAliveTimedOut) => {
                    debug!("keep-alive timed out, closing connection");
                    self.conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                }
                Poll::Pending => {}
            }
        }
    }
}

pin_project! {
    #[allow(missing_debug_implementations)]
    pub struct H2Stream<F, B, E>
    where
        B: Body,
    {
        reply: SendResponse<SendBuf<B::Data>>,
        #[pin]
        state: H2StreamState<F, B>,
        date_header: bool,
        informational: Option<InformationalReceiver>,
        // The pushes to promise on the stream (see `Http2Pushes`).
        pushes: Option<Http2PushStream<B>>,
        turns: Vec<Arc<PushTurn>>,
        exec: E,
        reset_requests: Option<ResetRequests>,
        // Its client's reset, while the service runs on, which it tells the service.
        reset: Option<(ResetRequest, Reason)>,
        // How its client's connection ended, but for a reset, while the service runs on.
        ended: Option<h2::Error>,
        stream_reset: Option<crate::ext::StreamReset>,
    }
}

pin_project! {
    #[project = H2StreamStateProj]
    enum H2StreamState<F, B>
    where
        B: Body,
    {
        Service {
            #[pin]
            fut: F,
            connect_parts: Option<ConnectParts>,
        },
        Body {
            #[pin]
            pipe: PipeToSendStream<B>,
        },
        // A bodiless response, sent once no more pushes can be promised on its stream.
        Bodiless {
            res: Option<::http::Response<()>>,
        },
    }
}

struct ConnectParts {
    pending: Pending,
    ping: Recorder,
    recv_stream: RecvStream,
}

impl<F, B, E> H2Stream<F, B, E>
where
    B: Body,
{
    fn new(
        fut: F,
        connect_parts: Option<ConnectParts>,
        respond: SendResponse<SendBuf<B::Data>>,
        date_header: bool,
        informational: Option<InformationalReceiver>,
        exec: E,
        reset_requests: Option<ResetRequests>,
        stream_reset: Option<crate::ext::StreamReset>,
    ) -> H2Stream<F, B, E> {
        H2Stream {
            reply: respond,
            state: H2StreamState::Service { fut, connect_parts },
            date_header,
            informational,
            pushes: None,
            turns: Vec::new(),
            exec,
            reset_requests,
            reset: None,
            ended: None,
            stream_reset,
        }
    }
}

/// Records a received request's field order as the `OriginalHeaderOrder` the HTTP/1
/// parser records, so a service sees repeats interleaved with other fields in place.
#[cfg(feature = "http1")]
fn record_header_order(extensions: &mut http::Extensions) {
    if let Some(h2::ext::HeaderOrder(names)) = extensions.remove::<h2::ext::HeaderOrder>() {
        let mut order = OriginalHeaderOrder::default();
        for name in names {
            order.append(name);
        }
        extensions.insert(order);
    }
}

/// Encodes a response's fields in its `OriginalHeaderOrder`, as the HTTP/1 encoder does.
#[cfg(feature = "http1")]
fn apply_header_order(res: &mut http::Response<()>) {
    if let Some(order) = res.extensions().get::<OriginalHeaderOrder>() {
        let names = order.get_in_order().map(|(name, _)| name.clone()).collect();
        res.extensions_mut().insert(h2::ext::HeaderOrder(names));
    }
}

/// Sends the interim (1xx) heads the service queued so far.
fn send_informational<B: Buf>(
    reply: &mut SendResponse<B>,
    informational: &mut Option<InformationalReceiver>,
    cx: &mut Context<'_>,
) {
    let Some(rx) = informational else {
        return;
    };
    while let Poll::Ready(Some(res)) = rx.poll_recv(cx) {
        #[cfg(feature = "http1")]
        let mut res = res;
        #[cfg(feature = "http1")]
        apply_header_order(&mut res);
        if let Err(_e) = reply.send_informational(res) {
            debug!("send informational error: {}", _e);
        }
    }
}

/// A response's head to send, as the client is to see it, and its body.
fn response_head<B>(res: Response<B>, date_header: bool) -> (::http::Response<()>, B) {
    let (head, body) = res.into_parts();
    let mut res = ::http::Response::from_parts(head, ());
    #[cfg(feature = "http1")]
    apply_header_order(&mut res);
    super::strip_connection_headers(res.headers_mut(), super::MessageKind::Response);

    // set Date header if it isn't already set if instructed
    if date_header {
        res.headers_mut()
            .entry(::http::header::DATE)
            .or_insert_with(date::update_and_header_value);
    }
    (res, body)
}

/// Promises the pushes queued so far on `reply`'s stream, each response sent by a task of its
/// own (its turn kept in `turns`), and tells whether the stream's end waits: more may come,
/// or a promised one's task has yet to send what it has ready. A push the client can't take
/// is dropped.
fn relay_pushes<B, E>(
    reply: &mut SendResponse<SendBuf<B::Data>>,
    pushes: &mut Option<Http2PushStream<B>>,
    turns: &mut Vec<Arc<PushTurn>>,
    exec: &E,
    date_header: bool,
    cx: &mut Context<'_>,
) -> bool
where
    B: Body,
    E: Http2PushExec<B>,
{
    let more = match pushes {
        Some(stream) => loop {
            match stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(push)) => match reply.push_request(push.request) {
                    Ok(reply) => {
                        let turn = PushTurn::new();
                        turns.push(Arc::clone(&turn));
                        exec.execute_push(H2Push {
                            reply,
                            state: H2PushState::Response { fut: push.response },
                            date_header,
                            relayed: false,
                            turn: PushTurnHeld(turn),
                        });
                    }
                    Err(_e) => {
                        debug!("push promise error: {}", _e);
                    }
                },
                Poll::Ready(None) => {
                    *pushes = None;
                    break false;
                }
                Poll::Pending => break true,
            }
        },
        None => false,
    };
    turns.retain(|turn| !turn.done.load(Ordering::Acquire));
    for turn in turns.iter() {
        turn.stream.register(cx.waker());
    }
    more || turns.iter().any(|turn| turn.busy())
}

/// A pushed response's progress, as the end of the stream it was promised on waits for it:
/// until its task is done, or was polled since it was last woken and what it sent went out,
/// what it has ready goes out ahead of that end, as the origin sent it ahead.
struct PushTurn {
    woken: AtomicUsize,
    polled: AtomicUsize,
    done: AtomicBool,
    task: AtomicWaker,
    stream: AtomicWaker,
}

impl PushTurn {
    fn new() -> Arc<Self> {
        Arc::new(PushTurn {
            // Not yet polled, it has its response to send.
            woken: AtomicUsize::new(1),
            polled: AtomicUsize::new(0),
            done: AtomicBool::new(false),
            task: AtomicWaker::new(),
            stream: AtomicWaker::new(),
        })
    }

    fn busy(&self) -> bool {
        !self.done.load(Ordering::Acquire)
            && self.woken.load(Ordering::Acquire) != self.polled.load(Ordering::Acquire)
    }
}

impl Wake for PushTurn {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.fetch_add(1, Ordering::AcqRel);
        self.task.wake();
    }
}

/// A push task's [`PushTurn`], done once the task drops it.
struct PushTurnHeld(Arc<PushTurn>);

impl Drop for PushTurnHeld {
    fn drop(&mut self) {
        self.0.done.store(true, Ordering::Release);
        self.0.stream.wake();
    }
}

macro_rules! reply {
    ($me:expr, $res:expr, $eos:expr) => {{
        match $me.reply.send_response($res, $eos) {
            Ok(tx) => tx,
            Err(e) => {
                debug!("send response error: {}", e);
                $me.reply.send_reset(Reason::INTERNAL_ERROR);
                return Poll::Ready(Err(crate::Error::new_h2(e)));
            }
        }
    }};
}

impl<F, B, Ex, E> H2Stream<F, B, Ex>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body + 'static,
    B::Data: 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    Ex: Http2UpgradedExec<B::Data> + Http2PushExec<B>,
    E: Into<Box<dyn StdError + Send + Sync>>,
{
    fn poll2(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        let mut me = self.as_mut().project();
        loop {
            let next = match me.state.as_mut().project() {
                H2StreamStateProj::Service {
                    fut: h,
                    connect_parts,
                } => {
                    let mut res = match h.poll(cx) {
                        // The client reset the stream: the response goes nowhere.
                        Poll::Ready(_) if me.reset.is_some() => {
                            let (_, reason) = me.reset.take().expect("the stream was reset");
                            return Poll::Ready(Err(crate::Error::new_h2(reason.into())));
                        }
                        // Nor once its connection ended.
                        Poll::Ready(_) if me.ended.is_some() => {
                            let ended = me.ended.take().expect("the connection ended");
                            return Poll::Ready(Err(crate::Error::new_h2(ended)));
                        }
                        Poll::Ready(Ok(r)) => r,
                        Poll::Pending => {
                            if me.reset.is_some() || me.ended.is_some() {
                                return Poll::Pending;
                            }
                            send_informational(me.reply, me.informational, cx);
                            // Response is not yet ready, so we want to check if the client has sent a
                            // RST_STREAM frame which would cancel the current request.
                            let reset = match me.reply.poll_reset(cx) {
                                // Its connection ended, but for a reset: the service runs on
                                // too, so that the request the client sent before goes on.
                                Poll::Ready(Err(e))
                                    if me.reset_requests.is_some()
                                        && matches!(
                                            e.get_io().map(std::io::Error::kind),
                                            Some(kind) if kind != std::io::ErrorKind::ConnectionReset
                                        ) =>
                                {
                                    debug!("stream's connection ended: {}", e);
                                    *me.ended = Some(e);
                                    *me.informational = None;
                                    return Poll::Pending;
                                }
                                reset => reset.map_err(crate::Error::new_h2)?,
                            };
                            if let Poll::Ready(reason) = reset {
                                debug!("stream received RST_STREAM: {:?}", reason);
                                match me.reset_requests.as_ref().and_then(ResetRequests::take) {
                                    Some(request) => {
                                        *me.reset = Some((request, reason));
                                        // Its interim heads go nowhere either.
                                        *me.informational = None;
                                        if let Some(stream_reset) = me.stream_reset.as_ref() {
                                            stream_reset.reset(reason.into());
                                        }
                                    }
                                    None => {
                                        return Poll::Ready(Err(crate::Error::new_h2(
                                            reason.into(),
                                        )))
                                    }
                                }
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            let err = crate::Error::new_user_service(e);
                            warn!("http2 service errored: {}", err);
                            me.reply.send_reset(err.h2_reason());
                            return Poll::Ready(Err(err));
                        }
                    };

                    // Interim heads queued before the final response still precede it.
                    send_informational(me.reply, me.informational, cx);
                    *me.informational = None;

                    *me.pushes = res
                        .extensions_mut()
                        .remove::<Http2Pushes<B>>()
                        .and_then(|pushes| pushes.take());
                    let (mut res, body) = response_head(res, *me.date_header);

                    if let Some(connect_parts) = connect_parts.take() {
                        if res.status().is_success() {
                            if headers::content_length_parse_all(res.headers())
                                .map_or(false, |len| len != 0)
                            {
                                warn!("h2 successful response to CONNECT request with body not supported");
                                me.reply.send_reset(h2::Reason::INTERNAL_ERROR);
                                return Poll::Ready(Err(crate::Error::new_user_header()));
                            }
                            if res
                                .headers_mut()
                                .remove(::http::header::CONTENT_LENGTH)
                                .is_some()
                            {
                                warn!("successful response to CONNECT request disallows content-length header");
                            }
                            let send_stream = reply!(me, res, false);
                            let (h2_up, up_task) = super::upgrade::pair(
                                send_stream,
                                connect_parts.recv_stream,
                                connect_parts.ping,
                            );
                            connect_parts
                                .pending
                                .fulfill(Upgraded::new(h2_up, Bytes::new()));
                            self.exec.execute_upgrade(up_task);
                            return Poll::Ready(Ok(()));
                        }
                    }

                    // The pushes queued so far are promised ahead of the response.
                    relay_pushes(me.reply, me.pushes, me.turns, me.exec, *me.date_header, cx);
                    if !body.is_end_stream() {
                        // automatically set Content-Length from body...
                        if let Some(len) = body.size_hint().exact() {
                            headers::set_content_length_if_missing(res.headers_mut(), len);
                        }

                        let raw_trailers = res.extensions().get::<RawTrailers>().cloned();
                        let body_tx = reply!(me, res, false);
                        H2StreamState::Body {
                            pipe: PipeToSendStream::new(body, body_tx, raw_trailers),
                        }
                    } else if me.pushes.is_some() {
                        H2StreamState::Bodiless { res: Some(res) }
                    } else {
                        reply!(me, res, true);
                        return Poll::Ready(Ok(()));
                    }
                }
                H2StreamStateProj::Body { mut pipe } => {
                    let pushing =
                        relay_pushes(me.reply, me.pushes, me.turns, me.exec, *me.date_header, cx);
                    pipe.as_mut().hold_end(pushing);
                    return pipe.poll(cx);
                }
                H2StreamStateProj::Bodiless { res } => {
                    if relay_pushes(me.reply, me.pushes, me.turns, me.exec, *me.date_header, cx) {
                        if let Poll::Ready(reason) =
                            me.reply.poll_reset(cx).map_err(crate::Error::new_h2)?
                        {
                            debug!("stream received RST_STREAM: {:?}", reason);
                            return Poll::Ready(Err(crate::Error::new_h2(reason.into())));
                        }
                        return Poll::Pending;
                    }
                    reply!(me, res.take().expect("polled after complete"), true);
                    return Poll::Ready(Ok(()));
                }
            };
            me.state.set(next);
        }
    }
}

impl<F, B, Ex, E> Future for H2Stream<F, B, Ex>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body + 'static,
    B::Data: 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
    Ex: Http2UpgradedExec<B::Data> + Http2PushExec<B>,
    E: Into<Box<dyn StdError + Send + Sync>>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll2(cx).map(|res| {
            if let Err(_e) = res {
                debug!("stream error: {}", _e);
            }
        })
    }
}

pin_project! {
    /// Sends a pushed response on its promised stream.
    #[allow(missing_debug_implementations)]
    pub struct H2Push<B>
    where
        B: Body,
    {
        reply: SendPushedResponse<SendBuf<B::Data>>,
        #[pin]
        state: H2PushState<B>,
        date_header: bool,
        relayed: bool,
        turn: PushTurnHeld,
    }
}

pin_project! {
    #[project = H2PushStateProj]
    enum H2PushState<B>
    where
        B: Body,
    {
        Response {
            fut: Pin<Box<dyn Future<Output = Result<Response<B>, Box<dyn StdError + Send + Sync>>> + Send>>,
        },
        Body {
            #[pin]
            pipe: PipeToSendStream<B>,
        },
    }
}

impl<B> Future for H2Push<B>
where
    B: Body,
    B::Data: 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let turn = Arc::clone(&self.turn.0);
        turn.task.register(cx.waker());
        let woken = turn.woken.load(Ordering::Acquire);
        let waker = Waker::from(Arc::clone(&turn));
        let cx = &mut Context::from_waker(&waker);
        if !self.relayed {
            let relayed = self.as_mut().relay(cx).is_ready();
            *self.as_mut().project().relayed = relayed;
        }
        let me = self.project();
        // What it sent goes out ahead of what the stream it was promised on sends next.
        if me.reply.poll_flushed(cx).is_pending() {
            return Poll::Pending;
        }
        turn.polled.store(woken, Ordering::Release);
        turn.stream.wake();
        if *me.relayed {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl<B> H2Push<B>
where
    B: Body,
    B::Data: 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    fn relay(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut me = self.project();
        loop {
            let next = match me.state.as_mut().project() {
                H2PushStateProj::Response { fut } => {
                    let res = match fut.as_mut().poll(cx) {
                        Poll::Ready(Ok(res)) => res,
                        Poll::Pending => {
                            if let Poll::Ready(_reason) = me.reply.poll_reset(cx) {
                                debug!("pushed stream received RST_STREAM: {:?}", _reason);
                                return Poll::Ready(());
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            let err = crate::Error::new_user_service(e);
                            debug!("pushed response errored: {}", err);
                            me.reply.send_reset(err.h2_reason());
                            return Poll::Ready(());
                        }
                    };
                    let (mut res, body) = response_head(res, *me.date_header);
                    let eos = body.is_end_stream();
                    if !eos {
                        if let Some(len) = body.size_hint().exact() {
                            headers::set_content_length_if_missing(res.headers_mut(), len);
                        }
                    }
                    let raw_trailers = res.extensions().get::<RawTrailers>().cloned();
                    match me.reply.send_response(res, eos) {
                        Ok(_) if eos => return Poll::Ready(()),
                        Ok(body_tx) => H2PushState::Body {
                            pipe: PipeToSendStream::new(body, body_tx, raw_trailers),
                        },
                        Err(_e) => {
                            debug!("send pushed response error: {}", _e);
                            me.reply.send_reset(Reason::INTERNAL_ERROR);
                            return Poll::Ready(());
                        }
                    }
                }
                H2PushStateProj::Body { pipe } => {
                    return pipe.poll(cx).map(|res| {
                        if let Err(_e) = res {
                            debug!("pushed stream error: {}", _e);
                        }
                    });
                }
            };
            me.state.set(next);
        }
    }
}
