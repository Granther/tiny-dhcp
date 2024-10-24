package cache

import (
	"fmt"
	"gdhcp/database"
	"gdhcp/types"
	"gdhcp/utils"
	"net"
	"time"
)

// Have a queue of available addrs
// When static addr is encountered, add to end of queue
// At runtime queue of N addrs is created
// If queue is empty, add additionalt pool of N available addrs (if possible)

type LeaseCacheHandler interface {
	IsMACLeased(mac net.HardwareAddr) net.IP
	IsIPAvailable(ip net.IP) bool
	UnleaseMAC(mac net.HardwareAddr)
	UnleaseIP(ip net.IP)
	Unlease(node *LeaseNode)
	LeaseIP(ip net.IP, mac net.HardwareAddr, leaseLen int) error
}

type LeaseCache struct {
	storage  database.PersistentHandler
	ipCache  map[[16]byte]*LeaseNode
	macCache map[string]*LeaseNode
}

type LeaseNode struct {
	ip       net.IP
	mac      net.HardwareAddr
	leaseLen time.Duration
	leasedOn time.Time
}

func NewLeaseCache(storage database.PersistentHandler, max int) LeaseCacheHandler {
	ipCache := make(map[[16]byte]*LeaseNode)
	macCache := make(map[string]*LeaseNode)

	return &LeaseCache{
		storage:  storage,
		ipCache:  ipCache,
		macCache: macCache,
	}
}

func NewLeaseNode(ip net.IP, mac net.HardwareAddr, leaseLen time.Duration, leasedOn time.Time) *LeaseNode {
	return &LeaseNode{
		ip:       ip,
		mac:      mac,
		leaseLen: leaseLen,
		leasedOn: leasedOn,
	}
}

func (l *LeaseCache) Put(newNode *LeaseNode) {
	ip := utils.IpTo16(newNode.ip)
	l.ipCache[*ip] = newNode
	l.macCache[newNode.mac.String()] = newNode
}

func (l *LeaseCache) IPGet(ip net.IP) *LeaseNode {
	ipBytes := utils.IpTo16(ip)
	val, ok := l.ipCache[*ipBytes]
	if ok {
		return val
	}
	return nil
}

func (l *LeaseCache) MACGet(mac net.HardwareAddr) *LeaseNode {
	val, ok := l.macCache[mac.String()]
	if ok {
		return val
	}
	return nil
}

func (l *LeaseCache) IPRemove(ip net.IP) {
	ipBytes := utils.IpTo16(ip)
	delete(l.ipCache, *ipBytes)
}

func (l *LeaseCache) MACRemove(mac net.HardwareAddr) {
	delete(l.macCache, mac.String())
}

func (l *LeaseCache) LeaseExpired(ip net.IP) bool {
	val := l.IPGet(ip)
	if val == nil {
		return true
	}

	timeSince := time.Since(val.leasedOn)
	return timeSince >= val.leaseLen
}

func (l *LeaseCache) PrintCache() {
	for _, val := range l.ipCache {
		fmt.Printf("IP: %v, MAC: %v\n", val.ip.String(), val.mac.String())
	}
}

func (l *LeaseCache) LeaseIP(ip net.IP, mac net.HardwareAddr, leaseLen int) error {
	leaseLenDur := time.Duration(leaseLen) * time.Second
	newNode := NewLeaseNode(ip, mac, leaseLenDur, time.Now())
	l.Put(newNode)

	l.storage.LeaseIP(newNode.ip, newNode.mac, newNode.leaseLen, newNode.leasedOn)

	return nil
}

func (l *LeaseCache) Unlease(node *LeaseNode) {
	l.Unleasestorage(node)
	l.IPRemove(node.ip)
}

func (l *LeaseCache) Unleasestorage(node *LeaseNode) error {
	storageLease := &types.DatabaseLease{
		IP:       node.ip.String(),
		MAC:      node.mac.String(),
		LeasedOn: utils.FormatTime(node.leasedOn),
		LeaseLen: int(node.leaseLen.Seconds()),
	}

	// Should sync, what if SQL fails
	l.storage.Unlease(storageLease)

	return nil
}

func (l *LeaseCache) UnleaseIP(ip net.IP) {
	node := l.IPGet(ip)
	l.Unlease(node)
}

func (l *LeaseCache) UnleaseMAC(mac net.HardwareAddr) {
	node := l.MACGet(mac)
	l.Unlease(node)
}

func (l *LeaseCache) IsIPAvailable(ip net.IP) bool {
	return l.IPGet(ip) == nil
}

func (l *LeaseCache) IsMACLeased(mac net.HardwareAddr) net.IP {
	node := l.MACGet(mac)
	if node == nil {
		return nil
	}

	return node.ip
}
