package cache

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"gdhcp/database"
	"gdhcp/types"
	"gdhcp/utils"
)

type CacheHandler interface {
	
}

type CacheManager struct {
	AddrPool    []string
	AddrQueue   *AddrQueue
	LeasesCache *LeasesCache
	PacketCache *PacketCache
	Storage     database.PersistentHandler
}

func NewCacheManager(packetCap int, packetTTL int, leasesMax int, queueMax int, addrPool []string, storage database.PersistentHandler) *CacheManager {
	slog.Debug("Creating new generate cache, and all children")

	return &CacheManager{
		AddrPool:    addrPool,
		AddrQueue:   NewAddrQueue(queueMax),
		LeasesCache: NewLeasesCache(leasesMax),
		PacketCache: NewPacketCache(packetCap, packetTTL),
		Storage:     storage,
	}
}

func (c *CacheManager) Init(num int) error {
	err := c.ReadLeasesFromDB()
	if err != nil {
		return nil
	}

	err = c.FillQueue(num)

	return err
}

func (c *CacheManager) ReadLeasesFromDB() error {
	// Read leases from db
	// Build leasenode object
	// Add to mac and ip cache
	leases, err := c.Storage.GetLeases()
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
		c.LeasesCache.Put(leaseNode)
	}

	return nil
}

func (c *CacheManager) FillQueue(num int) error {
	// While new addrs list < num
	// Generate addr from bottom of thing, if in cache or in queue, skip
	// else, add

	// Pass val to new addrs
	// If it has been longer than val.lease len since val.leased on, expired, add to back of queue as available

	// Clear Queue, fuck it
	c.AddrQueue.Empty()

	var newAddrs []net.IP
	startIP := net.ParseIP(c.AddrPool[0])
	endIP := net.ParseIP(c.AddrPool[1])

	for ip := startIP; !ip.Equal(endIP) && len(newAddrs) < num; ip = utils.IncrementIP(ip) {
		val := c.LeasesCache.IPGet(ip)
		if val == nil { // Doesnt exist in leases
			newAddrs = append(newAddrs, ip)
		}
	}

	// Add new addrs first (first to be picked)
	for _, ip := range newAddrs {
		ok := c.AddrQueue.EnQueue(ip)
		if !ok {
			slog.Debug("Wasn't able to add all addrs to queue, maybe full")
		}
	}

	return nil
}

func (c *CacheManager) LeaseIP(ip net.IP, mac net.HardwareAddr, leaseLen int) error {
	leaseLenDur := time.Duration(leaseLen) * time.Second
	newNode := NewLeaseNode(ip, mac, leaseLenDur, time.Now())
	c.LeasesCache.Put(newNode)

	c.Storage.LeaseIP(newNode.ip, newNode.mac, newNode.leaseLen, newNode.leasedOn)

	return nil
}

func (c *CacheManager) Unlease(node *LeaseNode) {
	c.UnleaseDB(node)
	c.LeasesCache.IPRemove(node.ip)
}

func (c *CacheManager) UnleaseDB(node *LeaseNode) error {
	dbLease := &types.DatabaseLease{
		IP:       node.ip.String(),
		MAC:      node.mac.String(),
		LeasedOn: utils.FormatTime(node.leasedOn),
		LeaseLen: int(node.leaseLen.Seconds()),
	}

	// Should sync, what if SQL fails
	c.Storage.Unlease(dbLease)

	return nil
}

func (c *CacheManager) UnleaseIP(ip net.IP) {
	node := c.LeasesCache.IPGet(ip)
	c.Unlease(node)
}

func (c *CacheManager) UnleaseMAC(mac net.HardwareAddr) {
	node := c.LeasesCache.MACGet(mac)
	c.Unlease(node)
}

func (c *CacheManager) IsIPAvailable(ip net.IP) bool {
	return c.LeasesCache.IPGet(ip) == nil
}

func (c *CacheManager) IsMACLeased(mac net.HardwareAddr) net.IP {
	node := c.LeasesCache.MACGet(mac)
	if node == nil {
		return nil
	}

	return node.ip
}
