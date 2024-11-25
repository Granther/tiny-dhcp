package cache

import (
	"fmt"
	"gdhcp/database"
	"gdhcp/types"
	"gdhcp/utils"
	"net"
	"time"
)

type PersistentCache struct {
	storage  database.PersistentHandler
	ipCache  map[[16]byte]*LeaseNode
	macCache map[string]*LeaseNode
}

func NewPersistentCache(storage database.PersistentHandler) LeaseCacheHandler {
	ipCache := make(map[[16]byte]*LeaseNode)
	macCache := make(map[string]*LeaseNode)

	return &PersistentCache{
		storage:  storage,
		ipCache:  ipCache,
		macCache: macCache,
	}
}

func (l *PersistentCache) Put(newNode *LeaseNode) {
	ip := utils.IpTo16(newNode.ip)
	l.ipCache[*ip] = newNode
	l.macCache[newNode.mac.String()] = newNode
}

func (l *PersistentCache) IPGet(ip net.IP) *LeaseNode {
	return nil
}

func (l *PersistentCache) MACGet(mac net.HardwareAddr) *LeaseNode {
	val, ok := l.macCache[mac.String()]
	if ok {
		return val
	}
	return nil
}

func (l *PersistentCache) IPRemove(ip net.IP) {
	ipBytes := utils.IpTo16(ip)
	delete(l.ipCache, *ipBytes)
}

func (l *PersistentCache) MACRemove(mac net.HardwareAddr) {
	delete(l.macCache, mac.String())
}

func (l *PersistentCache) LeaseExpired(ip net.IP) bool {
	val := l.IPGet(ip)
	if val == nil {
		return true
	}

	timeSince := time.Since(val.leasedOn)
	return timeSince >= val.leaseLen
}

func (l *PersistentCache) PrintCache() {
	for _, val := range l.ipCache {
		fmt.Printf("IP: %v, MAC: %v\n", val.ip.String(), val.mac.String())
	}
}

func (l *PersistentCache) LeaseIP(ip net.IP, mac net.HardwareAddr, leaseLen int) error {
	leaseLenDur := time.Duration(leaseLen) * time.Second
	newNode := NewLeaseNode(ip, mac, leaseLenDur, time.Now())
	l.Put(newNode)

	l.storage.LeaseIP(newNode.ip, newNode.mac, newNode.leaseLen, newNode.leasedOn)

	return nil
}

func (l *PersistentCache) Unlease(node *LeaseNode) {
	l.Unleasestorage(node)
	l.IPRemove(node.ip)
}

func (l *PersistentCache) Unleasestorage(node *LeaseNode) error {
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

func (l *PersistentCache) UnleaseIP(ip net.IP) {
	node := l.IPGet(ip)
	l.Unlease(node)
}

func (l *PersistentCache) UnleaseMAC(mac net.HardwareAddr) {
	node := l.MACGet(mac)
	l.Unlease(node)
}

func (l *PersistentCache) IsIPAvailable(ip net.IP) bool {
	return l.storage.IsIPAvailable(ip)
}

func (l *PersistentCache) IsMACLeased(mac net.HardwareAddr) net.IP {
	return l.storage.IsMACLeased(mac)
}

func (q *PersistentCache) ReadLeasesFromPersistent() error {
	// Read leases from db
	// Build leasenode object
	// Add to mac and ip cache
	leases, err := q.storage.GetLeases()
	if err != nil {
		return err
	}

	for _, lease := range leases {
		mac, err := net.ParseMAC(lease.MAC)
		if err != nil {
			return fmt.Errorf("unable to extract mac from database lease: %v", err)
		}

		leasedOn, err := time.Parse("2006-01-02 15:04:05", lease.LeasedOn)
		if err != nil {
			return fmt.Errorf("unable to parse str time from db to time: %v", err)
		}

		ip := net.ParseIP(lease.IP)

		leaseNode := NewLeaseNode(ip, mac, time.Duration(lease.LeaseLen), leasedOn)
		q.Put(leaseNode)
	}

	return nil
}
