package cache

import (
	"database/sql"
	"fmt"
	"net"
	"time"
)

// Have a queue of available addrs
// When static addr is encountered, add to end of queue
// At runtime queue of N addrs is created
// If queue is empty, add additionalt pool of N available addrs (if possible)

type LeasesCache struct {
	db       *sql.DB
	ipCache  map[[16]byte]*LeaseNode
	macCache map[string]*LeaseNode
}

type LeaseNode struct {
	ip       net.IP
	mac      net.HardwareAddr
	leaseLen time.Duration
	leasedOn time.Time
}

func NewLeaseNode(ip net.IP, mac net.HardwareAddr, leaseLen time.Duration, leasedOn time.Time) *LeaseNode {
	return &LeaseNode{
		ip:       ip,
		mac:      mac,
		leaseLen: leaseLen,
		leasedOn: leasedOn,
	}
}

func NewLeasesCache(db *sql.DB, max int) *LeasesCache {
	ipCache := make(map[[16]byte]*LeaseNode)
	macCache := make(map[string]*LeaseNode)

	return &LeasesCache{
		db:       db,
		ipCache:  ipCache,
		macCache: macCache,
	}
}

func (l *LeasesCache) Put(newNode *LeaseNode) {
	ip := IpTo16(newNode.ip)
	l.ipCache[*ip] = newNode
	l.macCache[newNode.mac.String()] = newNode
}

func (l *LeasesCache) IPGet(ip net.IP) *LeaseNode {
	ipBytes := IpTo16(ip)
	val, ok := l.ipCache[*ipBytes]
	if ok {
		return val
	}
	return nil
}

func (l *LeasesCache) MACGet(mac net.HardwareAddr) *LeaseNode {
	val, ok := l.macCache[mac.String()]
	if ok {
		return val
	}
	return nil
}

func (l *LeasesCache) IPRemove(ip net.IP) {
	ipBytes := IpTo16(ip)
	delete(l.ipCache, *ipBytes)
}

func (l *LeasesCache) MACRemove(mac net.HardwareAddr) {
	delete(l.macCache, mac.String())
}

func (l *LeasesCache) LeaseExpired(ip net.IP) bool {
	val := l.IPGet(ip)
	if val == nil {
		return true
	}

	timeSince := time.Since(val.leasedOn)
	return timeSince >= val.leaseLen
}

func (l *LeasesCache) PrintCache() {
	for _, val := range l.ipCache {
		fmt.Printf("IP: %v, MAC: %v\n", val.ip.String(), val.mac.String())
	}
}

func IpTo16(ip net.IP) *[16]byte {
	var ipArr [16]byte
	copy(ipArr[:], ip.To16())
	return &ipArr
}
