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

	// MacOS 上通常使用 "utun" 作为名称前缀，系统会自动分配 ID (如 utun0, utun1)
	// CreateTUN 会处理这些细节
	dev, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return
	}

	// 获取系统实际分配的接口名称
	realName, err := dev.Name()
	if err != nil {
		dev.Close()
		return
	}

	peer := cfg.Peer
	if peer == "" {
		peer = ip.String()
	}
	
	// 使用实际名称配置 IP
	cmd := fmt.Sprintf("ifconfig %s inet %s %s mtu %d up",
		realName, cfg.Addr, peer, mtu)
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
	err = errors.New("tap is not supported on darwin via wireguard-go")
	return
}

func addTunRoutes(ifName string, routes ...IPRoute) error {
	for _, route := range routes {
		if route.Dest == nil {
			continue
		}
		cmd := fmt.Sprintf("route add -net %s -interface %s", route.Dest.String(), ifName)
		log.Log("[tun]", cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}
