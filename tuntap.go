package gost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
    "strings"
	"sync/atomic"
	"sync"
	"time"

	"github.com/go-log/log"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/songgao/water/waterutil" // 这里保留 waterutil 用于解析包头，因为它纯粹是工具函数，不涉及设备I/O
	"github.com/xtaci/tcpraw"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/tun"
)

var mIPProts = map[waterutil.IPProtocol]string{
	waterutil.HOPOPT:     "HOPOPT",
	waterutil.ICMP:       "ICMP",
	waterutil.IGMP:       "IGMP",
	waterutil.GGP:        "GGP",
	waterutil.TCP:        "TCP",
	waterutil.UDP:        "UDP",
	waterutil.IPv6_Route: "IPv6-Route",
	waterutil.IPv6_Frag:  "IPv6-Frag",
	waterutil.IPv6_ICMP:  "IPv6-ICMP",
}

func ipProtocol(p waterutil.IPProtocol) string {
	if v, ok := mIPProts[p]; ok {
		return v
	}
	return fmt.Sprintf("unknown(%d)", p)
}

// IPRoute is an IP routing entry.
type IPRoute struct {
	Dest    *net.IPNet
	Gateway net.IP
}

// TunConfig is the config for TUN device.
type TunConfig struct {
	Name    string
	Addr    string
	Peer    string // peer addr of point-to-point on MacOS
	MTU     int
	Routes  []IPRoute
	Gateway string
}

type tunRouteKey [16]byte

func ipToTunRouteKey(ip net.IP) (key tunRouteKey) {
	copy(key[:], ip.To16())
	return
}

type tunListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	config TunConfig
}

// TunListener creates a listener for tun tunnel.
func TunListener(cfg TunConfig) (Listener, error) {
	threads := 1
	ln := &tunListener{
		conns:  make(chan net.Conn, threads),
		closed: make(chan struct{}),
		config: cfg,
	}

	for i := 0; i < threads; i++ {
		conn, ifce, err := createTun(cfg)
		if err != nil {
			return nil, err
		}
		ln.addr = conn.LocalAddr()

		log.Logf("[tun] %s: name: %s, mtu: %d",
			conn.LocalAddr(), ifce.Name, ifce.MTU)

		ln.conns <- conn
	}

	return ln, nil
}

func (l *tunListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
	}

	return nil, errors.New("accept on closed listener")
}

func (l *tunListener) Addr() net.Addr {
	return l.addr
}

func (l *tunListener) Close() error {
	select {
	case <-l.closed:
		return errors.New("listener has been closed")
	default:
		close(l.closed)
	}
	return nil
}

type tunHandler struct {
	options *HandlerOptions
	routes  sync.Map
	chExit  chan struct{}
}

// TunHandler creates a handler for tun tunnel.
func TunHandler(opts ...HandlerOption) Handler {
	h := &tunHandler{
		options: &HandlerOptions{},
		chExit:  make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(h.options)
	}

	return h
}

func (h *tunHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *tunHandler) Handle(conn net.Conn) {
	defer os.Exit(0)
	defer conn.Close()

	var err error
	var raddr net.Addr
	if addr := h.options.Node.Remote; addr != "" {
		raddr, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Logf("[tun] %s: remote addr: %v", conn.LocalAddr(), err)
			return
		}
	}

	var tempDelay time.Duration
	for {
		err := func() error {
			var err error
			var pc net.PacketConn
			// fake tcp mode will be ignored when the client specifies a chain.
			if raddr != nil && !h.options.Chain.IsEmpty() {
				cc, err := h.options.Chain.DialContext(context.Background(), "udp", raddr.String())
				if err != nil {
					return err
				}
				var ok bool
				pc, ok = cc.(net.PacketConn)
				if !ok {
					err = errors.New("not a packet connection")
					log.Logf("[tun] %s - %s: %s", conn.LocalAddr(), raddr, err)
					return err
				}
			} else {
				if h.options.TCPMode {
					if raddr != nil {
						pc, err = tcpraw.Dial("tcp", raddr.String())
					} else {
						pc, err = tcpraw.Listen("tcp", h.options.Node.Addr)
					}
				} else {
					laddr, _ := net.ResolveUDPAddr("udp", h.options.Node.Addr)
					pc, err = net.ListenUDP("udp", laddr)
				}
			}
			if err != nil {
				return err
			}

			pc, err = h.initTunnelConn(pc)
			if err != nil {
				return err
			}

			return h.transportTun(conn, pc, raddr)
		}()
		if err != nil {
			log.Logf("[tun] %s: %v", conn.LocalAddr(), err)
		}

		select {
		case <-h.chExit:
			return
		default:
		}

		if err != nil {
			if tempDelay == 0 {
				tempDelay = 1000 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 6 * time.Second; tempDelay > max {
				tempDelay = max
			}
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
	}
}

func (h *tunHandler) initTunnelConn(pc net.PacketConn) (net.PacketConn, error) {
	if len(h.options.Users) > 0 && h.options.Users[0] != nil {
		passwd, _ := h.options.Users[0].Password()
		cipher, err := core.PickCipher(h.options.Users[0].Username(), nil, passwd)
		if err != nil {
			return nil, err
		}
		pc = cipher.PacketConn(pc)
	}
	return pc, nil
}

func (h *tunHandler) findRouteFor(dst net.IP) net.Addr {
	if v, ok := h.routes.Load(ipToTunRouteKey(dst)); ok {
		return v.(net.Addr)
	}
	for _, route := range h.options.IPRoutes {
		if route.Dest.Contains(dst) && route.Gateway != nil {
			if v, ok := h.routes.Load(ipToTunRouteKey(route.Gateway)); ok {
				return v.(net.Addr)
			}
		}
	}
	return nil
}

// 检查是否是不可恢复的致命错误 (Socket文件被关闭)
func isFatalError(err error) bool {
	if err == nil {
		return false
	}
	// 1. 显式检查 net.ErrClosed
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// 2. 检查 io.EOF (对于 PacketConn 通常不应该出现，但为了安全)
	if err == io.EOF {
		return true
	}
	// 3. 字符串兜底检查
	// "use of closed network connection" 是 Go 标准库关闭 Socket 的报错
	msg := err.Error()
	if strings.Contains(msg, "closed network connection") {
		return true
	}
	return false
}

func (h *tunHandler) transportTun(tun net.Conn, conn net.PacketConn, raddr net.Addr) error {
	// 用于通知所有协程退出的通道
	// 只有当 tun 设备读写失败（致命）或 DPD 检测到死链时，才关闭此通道
	exitCh := make(chan struct{})
	var exitOnce sync.Once

	// 统一退出函数
	doExit := func() {
		exitOnce.Do(func() {
			close(exitCh)
		})
	}

	// DPD 配置
	//const (
	//	keepAliveInterval   = 15 * time.Second
	//	maxMissedKeepAlives = 3
	//)
	var missedKeepAlives int32 = 0

	// 错误通道 (仅接收导致重连的错误)
	errc := make(chan error, 1)

	// ---------------------------------------------------------
	// 协程 1: Keepalive Sender (Client Only)
	// ---------------------------------------------------------
	go func() {
        if !h.options.KeepAlive {
            return
        }
		keepAliveInterval := h.options.TTL
		if keepAliveInterval == 0 {
			keepAliveInterval = 10 * time.Second
		}
		maxMissedKeepAlives := int32(h.options.MaxFails)
		if maxMissedKeepAlives < 3 {
			maxMissedKeepAlives = 3
		}
		ticker := time.NewTicker(keepAliveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-exitCh:
				return
			case <-ticker.C:
				if raddr != nil {
					// DPD Check
					missed := atomic.AddInt32(&missedKeepAlives, 1)
					if missed > maxMissedKeepAlives {
						log.Logf("[tun] dead peer detected: no response for %d keepalives", missed)
						errc <- errors.New("dead peer detected")
						doExit()
						return
					}

					// 发送心跳
					_, err := conn.WriteTo(nil, raddr)
					if err != nil {
						// 如果是 Socket 关闭，退出；否则忽略错误
						if isFatalError(err) {
							return
						}
						// 记录日志但不退出
						if Debug {
							log.Logf("[tun] keepalive write error (ignored): %v", err)
						}
					} else {
						if Debug {
							log.Logf("[tun] sent keepalive (missed: %d)", missed)
						}
					}
				}
			}
		}
	}()

	// ---------------------------------------------------------
	// 协程 2: TUN -> Network (Read Path)
	// ---------------------------------------------------------
	go func() {
		defer doExit() // TUN 读失败通常意味着网卡没了，必须退出

		for {
			// 检查是否已被通知退出
			select {
			case <-exitCh:
				return
			default:
			}

			err := func() error {
				_b := sPool.Get().(*[]byte)
				defer sPool.Put(_b)
				b := *_b

				// 1. 读 TUN (这里出错是致命的)
				n, err := tun.Read(b)
				if err != nil {
					return err
				}

				// 准备数据包
				// Zero-Copy 优化：数据位于 b[16:]
				// 注意：这里 b 的切片操作要小心，Read 已经填充了 b[16:16+n]
				packet := b[wireguardOffset : wireguardOffset+n]

				// Client 发送逻辑
				if raddr != nil {
					_, err := conn.WriteTo(packet, raddr)
					if err != nil {
						// 【核心修改】忽略所有非致命网络错误
						if isFatalError(err) {
							return err
						}
						// 仅仅记录日志，为了不刷屏，可以只在 Debug 开启时记录
						// 这里 return nil 表示“本次包处理完毕”，继续循环
						return nil
					}
					return nil
				}

				// Server 转发逻辑
				var dst net.IP
				if waterutil.IsIPv4(packet) {
					header, _ := ipv4.ParseHeader(packet)
					dst = header.Dst
				} else if waterutil.IsIPv6(packet) {
					header, _ := ipv6.ParseHeader(packet)
					dst = header.Dst
				}

				addr := h.findRouteFor(dst)
				if addr == nil {
					return nil // 丢弃无路由包
				}

				if _, err := conn.WriteTo(packet, addr); err != nil {
					// 【核心修改】忽略转发错误
					if isFatalError(err) {
						return err
					}
					return nil
				}
				return nil
			}()

			if err != nil {
				// 只有 TUN 错误或 Socket Closed 才会走到这里
				errc <- err
				return
			}
		}
	}()

    // ---------------------------------------------------------
	// 协程 3: Network -> TUN (Write Path)
	// ---------------------------------------------------------
	go func() {
		defer doExit()

		for {
			select {
			case <-exitCh:
				return
			default:
			}

			err := func() error {
				_b := sPool.Get().(*[]byte)
				defer sPool.Put(_b)
				b := *_b

				// 1. 读取网络 (ReadFrom)
				//start := wireguardOffset
                //end := cap(b)
				//end := start + 1420//h.options.MTU
				//if end > cap(b) {
				//	end = cap(b)
				//}
				//buffToRead := b[start:end]
                buffToRead := b[wireguardOffset:cap(b)]
				n, addr, err := conn.ReadFrom(buffToRead)

				if err != nil {
					// 【核心修改】处理 Connection Refused
					if !isFatalError(err) {
						// 在 Server 重启期间，可能会疯狂收到 Connection Refused
						// 加一个小睡眠防止 CPU 100%
						time.Sleep(50 * time.Millisecond)
						if Debug {
							// log.Logf("[tun] network read error (ignored): %v", err)
						}
						return nil // 继续循环
					}

					// 过滤 Shadowsocks 短包错误
					if err != shadowaead.ErrShortPacket {
						return err
					}
					return nil
				}

				// 收到包，重置 DPD
				if raddr != nil {
					atomic.StoreInt32(&missedKeepAlives, 0)
				}

				// 处理 Keepalive
				if n == 0 {
					if Debug {
						log.Logf("[tun] keepalive from %s", addr)
					}
					if raddr == nil {
						// Server 回应
						conn.WriteTo(nil, addr)
					}
					return nil
				}

				// 写入 TUN
				fullPacket := b[:wireguardOffset+n]

				// 路由学习 (Server)
				if raddr == nil {
					packet := buffToRead[:n]
					var src net.IP
					if waterutil.IsIPv4(packet) {
						header, _ := ipv4.ParseHeader(packet)
						src = header.Src
					} else if waterutil.IsIPv6(packet) {
						header, _ := ipv6.ParseHeader(packet)
						src = header.Src
					}
					if src != nil {
						rkey := ipToTunRouteKey(src)
						h.routes.Store(rkey, addr)
					}
				}

				// 写入
				if _, err := tun.Write(fullPacket); err != nil {
					// TUN 写失败通常也是致命的
					return err
				}

				// 如果是 Server 且需要内部转发 (路由到其他 Peer)
				// 这里的逻辑稍微复杂，如果是 Server 模式，
				// 我们已经写入了 TUN (让内核处理)，通常内核会根据路由表再发回 TUN (Read Path)
				// 或者 gost 内部维护了 Peer 路由。
				// 原有代码有内部转发逻辑，这里补上：
				if raddr == nil {
					packet := buffToRead[:n]
					var dst net.IP
					if waterutil.IsIPv4(packet) {
						header, _ := ipv4.ParseHeader(packet)
						dst = header.Dst
					} else if waterutil.IsIPv6(packet) {
						header, _ := ipv6.ParseHeader(packet)
						dst = header.Dst
					}
					if targetAddr := h.findRouteFor(dst); targetAddr != nil {
						// 转发给另一个 client
						conn.WriteTo(packet, targetAddr)
						// 忽略发送错误
					}
				}

				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	// 等待退出
	<-exitCh

	// 尝试读取错误原因 (如果有)
	select {
	case err := <-errc:
		return err
	default:
		return nil
	}
}

var mEtherTypes = map[waterutil.Ethertype]string{
	waterutil.IPv4: "ip",
	waterutil.ARP:  "arp",
	waterutil.RARP: "rarp",
	waterutil.IPv6: "ip6",
}

func etherType(et waterutil.Ethertype) string {
	if s, ok := mEtherTypes[et]; ok {
		return s
	}
	return fmt.Sprintf("unknown(%v)", et)
}

// TapConfig is the config for TAP device.
type TapConfig struct {
	Name    string
	Addr    string
	MTU     int
	Routes  []string
	Gateway string
}

type tapRouteKey [6]byte

func hwAddrToTapRouteKey(addr net.HardwareAddr) (key tapRouteKey) {
	copy(key[:], addr)
	return
}

type tapListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}
	config TapConfig
}

// TapListener creates a listener for tap tunnel.
func TapListener(cfg TapConfig) (Listener, error) {
	threads := 1
	ln := &tapListener{
		conns:  make(chan net.Conn, threads),
		closed: make(chan struct{}),
		config: cfg,
	}

	for i := 0; i < threads; i++ {
		conn, ifce, err := createTap(cfg)
		if err != nil {
			return nil, err
		}
		ln.addr = conn.LocalAddr()

		log.Logf("[tap] %s: name: %s, mac: %s, mtu: %d",
			conn.LocalAddr(), ifce.Name, ifce.HardwareAddr, ifce.MTU)

		ln.conns <- conn
	}
	return ln, nil
}

func (l *tapListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
	}

	return nil, errors.New("accept on closed listener")
}

func (l *tapListener) Addr() net.Addr {
	return l.addr
}

func (l *tapListener) Close() error {
	select {
	case <-l.closed:
		return errors.New("listener has been closed")
	default:
		close(l.closed)
	}
	return nil
}

type tapHandler struct {
	options *HandlerOptions
	routes  sync.Map
	chExit  chan struct{}
}

// TapHandler creates a handler for tap tunnel.
func TapHandler(opts ...HandlerOption) Handler {
	h := &tapHandler{
		options: &HandlerOptions{},
		chExit:  make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(h.options)
	}

	return h
}

func (h *tapHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *tapHandler) Handle(conn net.Conn) {
	defer os.Exit(0)
	defer conn.Close()

	var err error
	var raddr net.Addr
	if addr := h.options.Node.Remote; addr != "" {
		raddr, err = net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Logf("[tap] %s: remote addr: %v", conn.LocalAddr(), err)
			return
		}
	}

	var tempDelay time.Duration
	for {
		err := func() error {
			var err error
			var pc net.PacketConn
			// fake tcp mode will be ignored when the client specifies a chain.
			if raddr != nil && !h.options.Chain.IsEmpty() {
				cc, err := h.options.Chain.DialContext(context.Background(), "udp", raddr.String())
				if err != nil {
					return err
				}
				var ok bool
				pc, ok = cc.(net.PacketConn)
				if !ok {
					err = errors.New("not a packet connection")
					log.Logf("[tap] %s - %s: %s", conn.LocalAddr(), raddr, err)
					return err
				}
			} else {
				if h.options.TCPMode {
					if raddr != nil {
						pc, err = tcpraw.Dial("tcp", raddr.String())
					} else {
						pc, err = tcpraw.Listen("tcp", h.options.Node.Addr)
					}
				} else {
					laddr, _ := net.ResolveUDPAddr("udp", h.options.Node.Addr)
					pc, err = net.ListenUDP("udp", laddr)
				}
			}
			if err != nil {
				return err
			}

			pc, err = h.initTunnelConn(pc)
			if err != nil {
				return err
			}

			return h.transportTap(conn, pc, raddr)
		}()
		if err != nil {
			log.Logf("[tap] %s: %v", conn.LocalAddr(), err)
		}

		select {
		case <-h.chExit:
			return
		default:
		}

		if err != nil {
			if tempDelay == 0 {
				tempDelay = 1000 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 6 * time.Second; tempDelay > max {
				tempDelay = max
			}
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0
	}
}

func (h *tapHandler) initTunnelConn(pc net.PacketConn) (net.PacketConn, error) {
	if len(h.options.Users) > 0 && h.options.Users[0] != nil {
		passwd, _ := h.options.Users[0].Password()
		cipher, err := core.PickCipher(h.options.Users[0].Username(), nil, passwd)
		if err != nil {
			return nil, err
		}
		pc = cipher.PacketConn(pc)
	}
	return pc, nil
}

func (h *tapHandler) transportTap(tap net.Conn, conn net.PacketConn, raddr net.Addr) error {
	errc := make(chan error, 1)

	go func() {
		for {
			err := func() error {
				_b := sPool.Get().(*[]byte)
				defer sPool.Put(_b)
				b := *_b

				n, err := tap.Read(b)
				if err != nil {
					select {
					case h.chExit <- struct{}{}:
					default:
					}
					return err
				}

				src := waterutil.MACSource(b[:n])
				dst := waterutil.MACDestination(b[:n])
				eType := etherType(waterutil.MACEthertype(b[:n]))

				if Debug {
					log.Logf("[tap] %s -> %s %s %d", src, dst, eType, n)
				}

				// client side, deliver frame directly.
				if raddr != nil {
					_, err := conn.WriteTo(b[:n], raddr)
					return err
				}

				// server side, broadcast.
				if waterutil.IsBroadcast(dst) {
					go h.routes.Range(func(k, v interface{}) bool {
						conn.WriteTo(b[:n], v.(net.Addr))
						return true
					})
					return nil
				}

				var addr net.Addr
				if v, ok := h.routes.Load(hwAddrToTapRouteKey(dst)); ok {
					addr = v.(net.Addr)
				}
				if addr == nil {
					log.Logf("[tap] no route for %s -> %s %s %d", src, dst, eType, n)
					return nil
				}

				if _, err := conn.WriteTo(b[:n], addr); err != nil {
					return err
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		for {
			err := func() error {
				_b := sPool.Get().(*[]byte)
				defer sPool.Put(_b)
				b := *_b

				n, addr, err := conn.ReadFrom(b)
				if err != nil &&
					err != shadowaead.ErrShortPacket {
					return err
				}

				src := waterutil.MACSource(b[:n])
				dst := waterutil.MACDestination(b[:n])
				eType := etherType(waterutil.MACEthertype(b[:n]))

				if Debug {
					log.Logf("[tap] %s -> %s %s %d", src, dst, eType, n)
				}

				// client side, deliver frame to tap device.
				if raddr != nil {
					_, err := tap.Write(b[:n])
					return err
				}

				// server side, record route.
				rkey := hwAddrToTapRouteKey(src)
				if actual, loaded := h.routes.LoadOrStore(rkey, addr); loaded {
					if actual.(net.Addr).String() != addr.String() {
						log.Logf("[tap] update route: %s -> %s (old %s)",
							src, addr, actual.(net.Addr))
						h.routes.Store(rkey, addr)
					}
				} else {
					log.Logf("[tap] new route: %s -> %s", src, addr)
				}

				if waterutil.IsBroadcast(dst) {
					go h.routes.Range(func(k, v interface{}) bool {
						if k.(tapRouteKey) != rkey {
							conn.WriteTo(b[:n], v.(net.Addr))
						}
						return true
					})
				}

				if v, ok := h.routes.Load(hwAddrToTapRouteKey(dst)); ok {
					if Debug {
						log.Logf("[tap] find route: %s -> %s", dst, v)
					}
					_, err := conn.WriteTo(b[:n], v.(net.Addr))
					return err
				}

				if _, err := tap.Write(b[:n]); err != nil {
					select {
					case h.chExit <- struct{}{}:
					default:
					}
					return err
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	err := <-errc
	if err != nil && err == io.EOF {
		err = nil
	}
	return err
}

// 头部预留长度 (VirtIO Net Header 占用)
//const wireguardOffset = 10

type tunTapConn struct {
	dev  tun.Device
	addr net.Addr
}

// Read 方法：TUN -> Network
// 优化策略：直接读取到 b[16:]，不进行内存移动。
// 【注意】：这打破了 io.Reader 的常规语义（数据通常从 b[0] 开始），
// 但为了极致性能，我们需要调用者配合处理偏移量。
func (c *tunTapConn) Read(b []byte) (n int, err error) {
	// 1. 确保容量足够
	if cap(b) < wireguardOffset {
		return 0, io.ErrShortBuffer
	}

	// 2. 将 b 扩展到最大容量
	// 我们把数据读到 buff 的 [16 : cap] 区间
	buff := b[:cap(b)]

	bufs := [][]byte{buff}
	sizes := []int{0}

	// 3. 调用 WireGuard Read
	// offset=16。内核头写入 0-16，IP 数据写入 16-end
	count, err := c.dev.Read(bufs, sizes, wireguardOffset)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, nil
	}

	// 返回读取到的数据长度 (不含头)
	// 调用者必须知道数据实际位于 b[16 : 16+n]
	return sizes[0], nil
}

// Write 方法：Network -> TUN
// 优化策略：假设调用者已经把数据放在了 b[16:]，且 b[0:16] 是可写的头部空间。
// Write 方法：Network -> TUN
func (c *tunTapConn) Write(b []byte) (n int, err error) {
	// 1. 检查长度
	if len(b) < wireguardOffset {
		return 0, nil
	}

	// 2. 【必须】头部清零 (解决脏数据导致的 GSO 错误)
	// 我们利用 Go 切片的特性，只清除前 10 字节。
	// 编译器会将此优化为高效的 memclr 指令，开销极低。
    if wireguardOffset > 0 {
        header := b[:wireguardOffset]
        for i := range header {
            header[i] = 0
        }
    }

	// 3. 构造参数 (Zero-Copy)
	bufs := [][]byte{b}

	// 4. 调用 WireGuard Write
	// offset=10。告诉驱动：数据从下标 10 开始。
	count, err := c.dev.Write(bufs, wireguardOffset)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, io.ErrShortWrite
	}

	return len(b) - wireguardOffset, nil
}

// 其他方法保持不变...
func (c *tunTapConn) Close() (err error) { return c.dev.Close() }
func (c *tunTapConn) LocalAddr() net.Addr { return c.addr }
func (c *tunTapConn) RemoteAddr() net.Addr { return &net.IPAddr{} }
func (c *tunTapConn) SetDeadline(t time.Time) error { return &net.OpError{Op: "set", Net: "tuntap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")} }
func (c *tunTapConn) SetReadDeadline(t time.Time) error { return &net.OpError{Op: "set", Net: "tuntap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")} }
func (c *tunTapConn) SetWriteDeadline(t time.Time) error { return &net.OpError{Op: "set", Net: "tuntap", Source: nil, Addr: nil, Err: errors.New("deadline not supported")} }
func IsIPv6Multicast(addr net.HardwareAddr) bool { return addr[0] == 0x33 && addr[1] == 0x33 }
