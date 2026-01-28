package gost

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/go-log/log"
	"golang.zx2c4.com/wireguard/tun"
)

const wireguardOffset = 10

func createTun(cfg TunConfig) (conn net.Conn, itf *net.Interface, err error) {
	ip, _, err := net.ParseCIDR(cfg.Addr)
	if err != nil {
		return
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	// 使用 WireGuard 库创建 TUN 设备
	dev, err := tun.CreateTUN(cfg.Name, mtu)
	if err != nil {
		return
	}

	// 获取实际生成的接口名称（例如 tun0）
	realName, err := dev.Name()
	if err != nil {
		dev.Close()
		return
	}

	// 配置 IP 地址
	if err = exeCmd(fmt.Sprintf("ip address add %s dev %s", cfg.Addr, realName)); err != nil {
		log.Log(err)
	}

	// 启动接口
	if err = exeCmd(fmt.Sprintf("ip link set dev %s up", realName)); err != nil {
		log.Log(err)
	}

    // 3. 【核心修复】关闭网卡的高级卸载功能 (GSO/GRO/TSO)
	// 这强制内核在把包交给 TUN 之前，严格按照 MTU 1420 进行分片。
	// 这样我们的程序读到的永远是 <= 1420 的小包，彻底根除 "too many segments" 和大包丢包问题。

	// 尝试使用 ethtool (最标准的方法)
	// 如果系统没有 ethtool，可能需要安装，或者忽略错误(但在生产环境建议必须有)
	if err = exeCmd(fmt.Sprintf("ethtool -K %s tx off tso off ufo off gso off gro off", realName)); err != nil {
		log.Log(err)
	}

	// 4. 设置队列长度 (可选，优化性能)
	exeCmd(fmt.Sprintf("ip link set dev %s qlen 1000", realName))

	if err = addTunRoutes(realName, cfg.Routes...); err != nil {
		dev.Close()
		return
	}

	itf, err = net.InterfaceByName(realName)
	if err != nil {
		dev.Close()
		return
	}

	conn = &tunTapConn{
		dev:  dev,
		addr: &net.IPAddr{IP: ip},
	}
	return
}

func createTap(cfg TapConfig) (conn net.Conn, itf *net.Interface, err error) {
	// 修正：wireguard-go/tun 库专为三层 (L3) 设计，未导出 CreateTAP 接口。
	// 为了使用该库的高性能特性，必须放弃 TAP 支持，或混合使用 water 库（不推荐，维护复杂）。
	err = errors.New("tap is not supported via wireguard-go/tun implementation")
	return
}

func addTunRoutes(ifName string, routes ...IPRoute) error {
	for _, route := range routes {
		if route.Dest == nil {
			continue
		}
		cmd := fmt.Sprintf("ip route add %s dev %s", route.Dest.String(), ifName)
		log.Logf("[tun] %s", cmd)

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			log.Logf("[tun] %s: %v", cmd, er)
		}
	}
	return nil
}

func addTapRoutes(ifName string, gw string, routes ...string) error {
	// TAP 已禁用，此函数亦不再需要实际逻辑
	return errors.New("tap routes not supported")
}

func exeCmd(cmd string) error {
	log.Log(cmd)

	args := strings.Split(cmd, " ")
	if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
		return fmt.Errorf("%s: %v", cmd, err)
	}

	return nil
}
