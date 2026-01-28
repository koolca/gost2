//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

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
	ip, _, err := net.ParseCIDR(cfg.Addr)
	if err != nil {
		return
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	// 在 BSD 系统上创建 TUN 设备
	dev, err := tun.CreateTUN(cfg.Name, mtu)
	if err != nil {
		return
	}

	realName, err := dev.Name()
	if err != nil {
		dev.Close()
		return
	}

	cmd := fmt.Sprintf("ifconfig %s inet %s mtu %d up", realName, cfg.Addr, mtu)
	log.Log("[tun]", cmd)
	args := strings.Split(cmd, " ")
	if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
		dev.Close()
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

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
	// WireGuard 核心库在大多数 Unix 平台上只暴露了 CreateTUN
	// 为了代码稳定性，此处禁用 TAP
	err = errors.New("tap is not supported on this platform via wireguard-go")
	return
}

func addTunRoutes(ifName string, routes ...IPRoute) error {
	for _, route := range routes {
		if route.Dest == nil {
			continue
		}
		cmd := fmt.Sprintf("route add -net %s -interface %s", route.Dest.String(), ifName)
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
