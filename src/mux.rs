//! 多路复用与 EOF 语义（docs/design.md §1.3.3d / §3.6，P1-9、VPN-14/16 协议侧）。
//!
//! - 复用器 = **rust-yamux 0.14.1**（hashicorp 规范实现；选型依据 vpn-mesh §4.1/S29/S30），
//!   跑在 session 记录层加密**之内**——流数/流元数据对中转不可见。链路次序：
//!   `TCP → 记录层（计数器 nonce AEAD）→ yamux → 逻辑流`。
//! - **禁依赖 TCP 半关闭**（frp T3 实证 SHUT_WR 整链即拆，frp-compat §1.5）：单向结束一律
//!   yamux FIN——即 [`Stream::finish`]；本包装类型**不实现** `poll_shutdown` 半关闭路径
//!   （底层 yamux `poll_close` 语义 = 发 FIN，仅在 `finish()` 内调用）。
//! - **心跳（§1.3.3d「keepalive = yamux ping 10s」的实现注记，如实声明）**：yamux 0.14.1
//!   的公开 API 只有 `Connection::poll_*`，**不暴露 ping 发起**（`on_ping` 仅应答入站
//!   ping；旧版 `Control::set_keep_alive_interval` 在 0.14 API 重构中移除，本次源码核实
//!   yamux-0.14.1/src/lib.rs Config 字段与 connection.rs）。故 10s 心跳由 session 记录层的
//!   加密 PING/PONG 帧承担（crypto-2026 §6.4 原始建议形态：保活帧本身也是加密帧），
//!   兼作中转探活；对端 yamux 若主动 ping，本侧 yamux 仍按规范自动应答。
//! - **优先级（如实声明）**：yamux 0.14.1 无流间调度优先级接口（帧发送在
//!   `Stream::poll_write` 内直接入队，无重排钩子）。M1 的「控制流高优先级」落位在 session
//!   记录层——会话控制记录（REKEY/PING/PONG）走独立高优先级通道，先于全部流数据下发
//!   （session::write_pump biased select）；[`Prio`] 是流级预留位，仅记录不重排。
//! - [`PacketChannel`]：TUN 包专用帧化 `[u16 len][ip packet]`（保边界），VPN-14 的库侧接口。

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::io::{AsyncRead, AsyncWrite};
use futures::{ready, Stream as FStream, StreamExt as _};

/// 逻辑流优先级档位（§3.6 `Prio` 调度档）。
///
/// M1 语义（见模块文档「优先级」注记）：[`Prio::Control`] 流登记为控制用途；
/// 会话级控制记录（rekey/心跳）始终先于流数据下发。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prio {
    /// 控制流档（OPAQUE 登录/配置下发等信令流）。
    Control,
    /// 普通数据档（默认）。
    Normal,
}

/// yamux 之上的逻辑流（包装 [`yamux::Stream`]，§3.6 接口：AsyncRead/Write + 显式 finish）。
///
/// EOF 语义：`finish()` = 发送 yamux FIN（单向结束），**绝不触碰 TCP 半关闭**；
/// 对端读到 0 字节即收到 EOF。整流全关由会话层 teardown 承担。
pub struct Stream {
    inner: yamux::Stream,
    prio: Prio,
}

impl Stream {
    pub(crate) fn new(inner: yamux::Stream, prio: Prio) -> Self {
        Stream { inner, prio }
    }

    /// 流 ID（yamux：客户端打开的流为奇数、服务器打开为偶数；客户端**首条流 = 1**）。
    ///
    /// 供装配层做流分派（§3.12：首流 = 控制流）——按 ID 分派对 yamux 的惰性 SYN
    /// （流在首帧数据前不物化）免疫：被静默持有的控制流（id=1）即使从未物化，
    /// 后续物化的数据流（id≥3）也能被正确识别为数据面。
    pub fn id(&self) -> u32 {
        self.inner.id().val()
    }

    /// 取回内部 yamux 流（inbound 暂存回退路径用，库外无意义）。
    pub(crate) fn into_inner(self) -> yamux::Stream {
        self.inner
    }

    /// 该流的优先级档位。
    pub fn prio(&self) -> Prio {
        self.prio
    }

    /// 显式单向结束：发送 yamux FIN（§1.3.3d 禁半关闭——FIN 是唯一 sanctioned 路径）。
    /// 之后的 [`Stream::write_all`] 返回错误；对端读端将观察到 EOF。
    pub async fn finish(&mut self) -> io::Result<()> {
        futures::AsyncWriteExt::close(&mut self.inner).await
    }

    /// 写全部字节（分片 ≤ 记录层单帧上限由 MuxIo 内部处理）。
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        futures::AsyncWriteExt::write_all(&mut self.inner, buf).await
    }

    /// 读满 `buf`；对端 FIN 后不足即 `UnexpectedEof`，0 长度 buf 立即 Ok。
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        futures::AsyncReadExt::read_exact(&mut self.inner, buf)
            .await
            .map(|_| ())
    }

    /// 读至多 `buf.len()` 字节；`Ok(0)` = 对端 FIN（EOF）。
    pub async fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        futures::AsyncReadExt::read(&mut self.inner, buf).await
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// **不支持**（禁半关闭：不提供隐式 shutdown 路径，单向结束必须显式 [`Stream::finish`]）。
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mux: implicit shutdown disabled; use Stream::finish()",
        )))
    }
}

/// TUN 包通道（§1.3.6/§3.6 `PacketChannel`，VPN-14 库侧接口）。
///
/// 帧化：`[u16 LE len][ip packet]`（保包边界）。单包上限 65535B（u16 长度域）；
/// 部署形态 MTU 1280（§2.1）远小于该上限。
pub struct PacketChannel {
    stream: Stream,
}

/// 单包长度上限（帧头 u16）。
pub const MAX_PACKET: usize = u16::MAX as usize;

/// 发一个包帧（`[u16 LE len][pkt]`；与 [`PacketChannel::send`] 同一线上格式）。
///
/// 独立函数形态供「读/写分离 + 专职任务」的装配使用——select 循环内直接 await
/// [`PacketChannel::recv`] **不具备取消安全**（帧化是两次 read_exact：半途 future
/// 被丢弃 ⇒ 已消费的帧头/帧体字节丢失，帧流永久失步）。写侧无此问题：写完整帧
/// 在分支体内 await 至完成。
pub async fn send_packet<W>(w: &mut W, pkt: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use futures::AsyncWriteExt as _;
    if pkt.len() > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mux: packet exceeds u16 frame limit (65535B)",
        ));
    }
    let mut frame = Vec::with_capacity(2 + pkt.len());
    frame.extend_from_slice(&(pkt.len() as u16).to_le_bytes());
    frame.extend_from_slice(pkt);
    w.write_all(&frame).await
}

/// 收一个包帧（对端 FIN 且无残包 ⇒ `UnexpectedEof`）。
///
/// 取消安全注意：本函数内部仍是两次 read_exact——**只在专职读任务里循环使用**
/// （任务不被 select 取消，半途状态安全保存在自身的执行栈上）。
pub async fn recv_packet<R>(r: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    use futures::AsyncReadExt as _;
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_le_bytes(hdr) as usize;
    let mut pkt = vec![0u8; len];
    r.read_exact(&mut pkt).await?;
    Ok(pkt)
}

impl PacketChannel {
    /// 装配（出站 `Tunnel::open_packet_channel` 与接受侧 `accept_stream` 配套共用；
    /// ponytail：合并原 new/from_stream 双构造同体）。
    pub fn from_stream(stream: Stream) -> Self {
        PacketChannel { stream }
    }

    /// 消费为底层流（chunked 注入等测试路径用）。
    pub fn into_stream(self) -> Stream {
        self.stream
    }

    /// 发一个 IP 包：`[u16 len][pkt]`。
    pub async fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        send_packet(&mut self.stream, pkt).await
    }

    /// 收一个 IP 包。对端 FIN 且无残包 ⇒ `UnexpectedEof`。
    pub async fn recv(&mut self) -> io::Result<Vec<u8>> {
        recv_packet(&mut self.stream).await
    }

    /// 单向结束（透传 [`Stream::finish`] 的 yamux FIN 语义）。
    pub async fn finish(&mut self) -> io::Result<()> {
        self.stream.finish().await
    }

    /// 消费为包迭代流（§3.6 `recv_stream()`）：逐包产出，错误/EOF 终止。
    pub fn recv_stream(self) -> PacketRx {
        PacketRx {
            framer: FrameRx::new(self.stream),
        }
    }
}

/// `[u16 LE len][pkt]` 帧化解码状态机（[`PacketRx`] 的内核）。
///
/// 帧化状态（2B 头 + 部分体缓冲）是**结构体字段**——跨 poll/跨唤醒保留。泛型化在
/// 读取面 `R` 上，使「包体分多次唤醒到达」可用 mock 读取器直接做回归测试
/// （[`PacketChannel::recv`]/[`recv_packet`] 的两次 read_exact 形态没有跨调用状态，
/// 包体半途 future 被丢弃即帧流永久失步，见 `send_packet` 的取消安全注记）。
pub(crate) struct FrameRx<R> {
    r: R,
    hdr: [u8; 2],
    hdr_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
}

impl<R: AsyncRead + Unpin> FrameRx<R> {
    pub(crate) fn new(r: R) -> Self {
        FrameRx {
            r,
            hdr: [0; 2],
            hdr_filled: 0,
            body: Vec::new(),
            body_filled: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> FStream for FrameRx<R> {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // 帧头：2B 增量填满（每次 poll_read 至多推进一段，Pending 即带着已收字节返回）。
        while this.hdr_filled < this.hdr.len() {
            match Pin::new(&mut this.r).poll_read(cx, &mut this.hdr[this.hdr_filled..]) {
                // EOF ⇒ 沿 recv_packet 的 read_exact→UnexpectedEof→None 语义（含半帧截断）。
                Poll::Ready(Ok(0)) => return Poll::Ready(None),
                Poll::Ready(Ok(n)) => this.hdr_filled += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
        if this.body.is_empty() && this.body_filled == 0 {
            let len = u16::from_le_bytes(this.hdr) as usize;
            this.body = vec![0u8; len];
        }
        while this.body_filled < this.body.len() {
            match Pin::new(&mut this.r).poll_read(cx, &mut this.body[this.body_filled..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(None),
                Poll::Ready(Ok(n)) => this.body_filled += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
        let pkt = std::mem::take(&mut this.body);
        this.body_filled = 0;
        this.hdr_filled = 0;
        Poll::Ready(Some(Ok(pkt)))
    }
}

/// [`PacketChannel::recv_stream`] 的产物：`futures::Stream<Item = io::Result<Vec<u8>>>`。
///
/// 帧化状态保存在 [`FrameRx`] 字段内跨 poll 复用——包体分多次唤醒到达时不再把
/// body 首 2 字节误读为新帧头（回归测试 `packet_rx_frames_survive_split_arrival`）。
pub struct PacketRx {
    framer: FrameRx<Stream>,
}

impl FStream for PacketRx {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().framer.poll_next_unpin(cx)
    }
}

// —— 供 session 内部装配的 yamux 帧承载 IO（明文管道：记录层已加密/解密）——

/// 在途 data 通道发送 future（tokio mpsc 无 poll 式 reserve，故存自引用 future）。
type SendFut =
    Pin<Box<dyn Future<Output = Result<(), tokio::sync::mpsc::error::SendError<Vec<u8>>>> + Send>>;

/// yamux 承载 IO：读端 = 读泵投递的已解密 DATA 记录；写端 = 待封装 payload 交写泵
/// （封装在写泵唯一串行点执行，保证记录计数器顺序 = 实际上线顺序）。
pub(crate) struct MuxIo {
    pub(crate) plain_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pub(crate) data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub(crate) rbuf: Vec<u8>,
    pub(crate) send_fut: Option<SendFut>,
    pub(crate) send_len: usize,
}

impl MuxIo {
    /// 装配构造子（session::spawn_session 用）。
    pub(crate) fn new(
        plain_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        data_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Self {
        MuxIo {
            plain_rx,
            data_tx,
            rbuf: Vec::new(),
            send_fut: None,
            send_len: 0,
        }
    }
}

impl AsyncRead for MuxIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.rbuf.is_empty() {
            match ready!(self.plain_rx.poll_recv(cx)) {
                Some(payload) => self.rbuf = payload,
                None => return Poll::Ready(Ok(0)), // 会话关闭（对端 EOF/本侧 kill）
            }
        }
        let n = buf.len().min(self.rbuf.len());
        buf[..n].copy_from_slice(&self.rbuf[..n]);
        self.rbuf.drain(..n);
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for MuxIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 分片上限：单条记录 payload ≤ 1MiB（§1.3.3c 记录层不变量）；64KiB 保证
        // 记录粒度细腻且不触碰上限。
        if self.send_fut.is_none() {
            let n = buf.len().min(64 * 1024);
            self.send_len = n;
            // async move 块持有克隆的 Sender ⇒ future 'static（send 借用 &self）。
            let tx = self.data_tx.clone();
            let chunk = buf[..n].to_vec();
            self.send_fut = Some(Box::pin(async move { tx.send(chunk).await }));
        }
        let this = &mut *self;
        match this.send_fut.as_mut().expect("just set").as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                this.send_fut = None;
                Poll::Ready(Ok(this.send_len))
            }
            Poll::Ready(Err(_)) => {
                // 完成的 future 必须清出 send_fut：yamux 在写错误后会重试 poll_write，
                // 复轮询已完成 future 会以「async fn resumed after completion」panic
                //（实测杀掉 mux 驱动任务、扰乱会话拆除时序——A9 死链检测被拖延）。
                this.send_fut = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mux: record writer gone",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // 有界通道满即背压，flush 无独立语义
    }

    /// 禁半关闭：对承载 IO 不做任何 shutdown（整链拆除由会话层统一负责）。
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prio_values() {
        assert_ne!(Prio::Control, Prio::Normal);
    }

    /// 分片到达 mock（延迟投递）：每次 poll_read 弹出一个预置 chunk（块大于请求 buf 时
    /// 保留剩余字节下次续读）；队列空 ⇒ Pending（noop waker 不会自动重唤，由测试手动
    /// 再 poll——精确控制「跨唤醒到达」的字节切面）；`eof = true` 后返回 Ok(0) 模拟 FIN。
    struct TrickleReader {
        chunks: std::collections::VecDeque<Vec<u8>>,
        eof: bool,
    }

    impl AsyncRead for TrickleReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            match self.chunks.pop_front() {
                Some(mut c) => {
                    let n = c.len().min(buf.len());
                    buf[..n].copy_from_slice(&c[..n]);
                    if n < c.len() {
                        c.drain(..n);
                        self.chunks.push_front(c);
                    }
                    Poll::Ready(Ok(n))
                }
                None if self.eof => Poll::Ready(Ok(0)),
                None => Poll::Pending,
            }
        }
    }

    /// 回归（评审确认缺陷）：旧 PacketRx 每次 poll 新建 `ch.recv()` future、Pending 即丢
    /// ——包体跨唤醒到达时已消费的帧头/帧体状态丢失，body 首 2 字节被当新帧头，帧流
    /// 永久失步。帧化状态上移 FrameRx 字段后：逐字节分片到达（每字节一次 poll、期间
    /// 多次返回 Pending）必须完整分帧。
    #[test]
    fn packet_rx_frames_survive_split_arrival() {
        use futures::task::noop_waker;
        use futures::StreamExt as _;

        let pkt1: Vec<u8> = (0..40u8).collect();
        let pkt2: Vec<u8> = vec![0xA5; 5];
        let pkt3: Vec<u8> = Vec::new(); // 0 长度包（合法帧：len=0）
        let mut wire: Vec<u8> = Vec::new();
        for p in [&pkt1, &pkt2, &pkt3] {
            wire.extend_from_slice(&(p.len() as u16).to_le_bytes());
            wire.extend_from_slice(p);
        }

        let reader = TrickleReader {
            chunks: std::collections::VecDeque::new(),
            eof: false,
        };
        let mut rx = FrameRx::new(reader);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut got: Vec<Vec<u8>> = Vec::new();
        for &b in &wire {
            // 每次只投递 1 字节再 poll：帧未齐 ⇒ Pending（旧实现的半途 future 在此被
            // 丢弃、下一 poll 从 body 字节重建帧头）；帧齐 ⇒ Ready 收包。
            rx.r.chunks.push_back(vec![b]);
            loop {
                match rx.poll_next_unpin(&mut cx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(p))) => got.push(p),
                    Poll::Ready(Some(Err(e))) => panic!("分片到达分帧错误: {e}"),
                    Poll::Ready(None) => panic!("数据未尽即 EOF"),
                }
            }
        }
        assert_eq!(got, vec![pkt1, pkt2, pkt3], "分片到达逐包逐字节完整且有序");

        // 全部帧收完 ⇒ Pending（等更多数据）；FIN ⇒ None 收尾。
        assert!(rx.poll_next_unpin(&mut cx).is_pending());
        rx.r.eof = true;
        assert!(matches!(rx.poll_next_unpin(&mut cx), Poll::Ready(None)));
    }

    /// 分片到达回归的第二形态：帧头/帧体按「粗块」跨 poll 到达（帧头一块、帧体两半、
    /// 下一帧紧随其后同块）——每块投递后 poll 至 Pending，半途状态跨 poll 保留。
    #[test]
    fn packet_rx_frames_survive_chunked_body_arrival() {
        use futures::task::noop_waker;
        use futures::StreamExt as _;

        let pkt1: Vec<u8> = (0..100u8).collect();
        let pkt2: Vec<u8> = vec![0x5A; 3];
        let frame1 = {
            let mut f = (pkt1.len() as u16).to_le_bytes().to_vec();
            f.extend_from_slice(&pkt1);
            f
        };
        let frame2 = {
            let mut f = (pkt2.len() as u16).to_le_bytes().to_vec();
            f.extend_from_slice(&pkt2);
            f
        };

        let reader = TrickleReader {
            chunks: std::collections::VecDeque::new(),
            eof: false,
        };
        let mut rx = FrameRx::new(reader);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut got: Vec<Vec<u8>> = Vec::new();
        let chunks = vec![
            frame1[..2].to_vec(),                     // 帧 1 头（体未到 ⇒ Pending）
            frame1[2..52].to_vec(),                   // 帧 1 体前半（半途 ⇒ Pending）
            [frame1[52..].to_vec(), frame2].concat(), // 帧 1 体后半 + 整帧 2 同块
        ];
        for c in chunks {
            rx.r.chunks.push_back(c);
            loop {
                match rx.poll_next_unpin(&mut cx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(p))) => got.push(p),
                    Poll::Ready(Some(Err(e))) => panic!("分块到达分帧错误: {e}"),
                    Poll::Ready(None) => panic!("数据未尽即 EOF"),
                }
            }
        }
        assert_eq!(got, vec![pkt1, pkt2], "块边界跨 poll 分帧完整");
        rx.r.eof = true;
        assert!(matches!(rx.poll_next_unpin(&mut cx), Poll::Ready(None)));
    }

    /// 红形态对照（证明上述回归测试有牙）：与修复前 PacketRx 同构的实现——每次
    /// poll 新建「两次 read_exact」的 recv future、Pending 即丢。同一分片到达输入下
    /// 必然失步：帧头读半 ⇒ 丢弃，下一 poll 把 body 首字节当新帧头重组出错误帧。
    struct OldFrameRx<R> {
        r: R,
    }

    impl<R: AsyncRead + Unpin> FStream for OldFrameRx<R> {
        type Item = io::Result<Vec<u8>>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let r = &mut self.get_mut().r;
            let mut fut = std::pin::pin!(async {
                let mut hdr = [0u8; 2];
                futures::AsyncReadExt::read_exact(r, &mut hdr).await?;
                let len = u16::from_le_bytes(hdr) as usize;
                let mut pkt = vec![0u8; len];
                futures::AsyncReadExt::read_exact(r, &mut pkt).await?;
                Ok::<_, io::Error>(pkt)
            });
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(pkt)) => Poll::Ready(Some(Ok(pkt))),
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    Poll::Ready(None)
                }
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    #[test]
    fn old_recreate_future_pattern_desyncs_on_split_arrival() {
        use futures::task::noop_waker;
        use futures::StreamExt as _;

        let pkt: Vec<u8> = (0..40u8).collect();
        let mut wire: Vec<u8> = Vec::new();
        wire.extend_from_slice(&(pkt.len() as u16).to_le_bytes());
        wire.extend_from_slice(&pkt);

        let mut old = OldFrameRx {
            r: TrickleReader {
                chunks: std::collections::VecDeque::new(),
                eof: false,
            },
        };
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut got: Vec<Vec<u8>> = Vec::new();
        for &b in &wire {
            old.r.chunks.push_back(vec![b]);
            loop {
                match old.poll_next_unpin(&mut cx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(p))) => got.push(p),
                    Poll::Ready(Some(Err(e))) => panic!("红形态对照不应报错: {e}"),
                    Poll::Ready(None) => panic!("数据未尽即 EOF"),
                }
            }
        }
        // 失步实锤：同一输入下，旧形态产不出与线上一致的包序列（帧头半途被丢 ⇒
        // 后续字节被重组成错误长度的帧）。
        assert_ne!(
            got,
            vec![pkt.clone()],
            "旧形态若能正确分帧，则缺陷不存在——此断言失败说明输入未覆盖分片路径"
        );
    }

    /// 回归（A9 排障实测）：写泵消失（会话拆除 ⇒ data_rx drop）后 send 立即 Err；
    /// yamux 在写错误后会重试 poll_write——已完成 future 必须已清出 `send_fut`，
    /// 否则复轮询以「async fn resumed after completion」panic（杀 mux 驱动任务，
    /// 拖延死链拆除时序）。
    #[test]
    fn muxio_write_err_then_repoll_returns_err_without_panic() {
        use futures::task::noop_waker;
        use std::task::Context;

        let (data_tx, data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let (_plain_hold, plain_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        drop(data_rx); // 写泵消失（通道无接收者 ⇒ send 立即 Err）

        let mut io = MuxIo::new(plain_rx, data_tx);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let first = std::pin::Pin::new(&mut io).poll_write(&mut cx, b"payload");
        match first {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            other => panic!("期望 Ready(Err(BrokenPipe))，得 {other:?}"),
        }
        // 复轮询（yamux 写重试形态）：不得 panic，且再次给出 BrokenPipe。
        let second = std::pin::Pin::new(&mut io).poll_write(&mut cx, b"payload");
        match second {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            other => panic!("复轮询期望 Ready(Err(BrokenPipe))，得 {other:?}"),
        }
    }
}
