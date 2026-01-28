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

const wireguardOffset = 0

func createTun(cfg TunConfig) (conn net.Conn, itf *net.Interface, err error) {
	ip, ipNet, err := net.ParseCIDR(cfg.Addr)
	if err != nil {
		return
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	// WireGuard 在 Windows 上使用 Wintun 驱动
	// 它不需要像 TAP-Windows 那样指定 ComponentID
	dev, err := tun.CreateTUN(cfg.Name, mtu)
	if err != nil {
		return
	}

	realName, err := dev.Name()
	if err != nil {
		dev.Close()
		return
	}

	// 配置 Wintun 接口的 IP 地址
	// 注意：Wintun 接口创建后通常是 "Up" 状态，但需要 IP 配置
	cmd := fmt.Sprintf("netsh interface ip set address name=\"%s\" "+
		"source=static addr=%s mask=%s gateway=none",
		realName, ip.String(), ipMask(ipNet.Mask))
	log.Log("[tun]", cmd)
	args := strings.Split(cmd, " ")
	if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
		dev.Close()
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	if err = addTunRoutes(realName, cfg.Gateway, cfg.Routes...); err != nil {
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
	// wireguard-go 的 Windows 实现基于 Wintun (Layer 3 TUN)。
	// 它不支持传统的 TAP (Layer 2) 模式。
	err = errors.New("tap is not supported on windows via wireguard-go (wintun only supports layer 3)")
	return
}

func addTunRoutes(ifName string, gw string, routes ...IPRoute) error {
	for _, route := range routes {
		if route.Dest == nil {
			continue
		}

		deleteRoute(ifName, route.Dest.String())

		cmd := fmt.Sprintf("netsh interface ip add route prefix=%s interface=\"%s\" store=active",
			route.Dest.String(), ifName)
		if gw != "" {
			cmd += " nexthop=" + gw
		}
		log.Logf("[tun] %s", cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}

func addTapRoutes(ifName string, gw string, routes ...string) error {
	return errors.New("tap routes not supported")
}

func deleteRoute(ifName string, route string) error {
	cmd := fmt.Sprintf("netsh interface ip delete route prefix=%s interface=\"%s\" store=active",
		route, ifName)
	args := strings.Split(cmd, " ")
	return exec.Command(args[0], args[1:]...).Run()
}

func ipMask(mask net.IPMask) string {
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
