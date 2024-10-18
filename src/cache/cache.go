package cache

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"time"

	database "gdhcp/database"
	types "gdhcp/types"
)

type Cache struct {
	AddrPool    []string
	AddrQueue   *AddrQueue
	LeasesCache *LeasesCache
	PacketCache *PacketCache
}

func NewCache(packetCap int, packetTTL int, leasesMax int, queueMax int, addrPool []string, db *sql.DB) *Cache {
	slog.Debug("Creating new generat cache, and all children")

	return &Cache{
		AddrPool:    addrPool,
		AddrQueue:   NewAddrQueue(queueMax),
		LeasesCache: NewLeasesCache(db, leasesMax),
		PacketCache: NewPacketCache(packetCap, packetTTL),
	}
}

func (c *Cache) Init(db *sql.DB, num int) error {
	err := c.ReadLeasesFromDB(db)
	if err != nil {
		return nil
	}

	err = c.FillQueue(num)

	return err
}

func (c *Cache) ReadLeasesFromDB(db *sql.DB) error {
	// Read leases from db
	// Build leasenode object
	// Add to mac and ip cache
	leases, err := database.GetLeases(db)
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

func (c *Cache) FillQueue(num int) error {
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

	for ip := startIP; !ip.Equal(endIP) && len(newAddrs) < num; ip = database.IncrementIP(ip) {
		val := c.LeasesCache.IPGet(ip)
		if val == nil { // Doesnt exist in leases
			newAddrs = append(newAddrs, ip)
		}
	}

	for _, ip := range newAddrs {
		ok := c.AddrQueue.enQueue(ip)
		if !ok {
			slog.Debug("Wasn't able to add all addrs to queue, maybe full")
			return nil
		}
	}

	return nil
}

func (c *Cache) LeaseIP(ip net.IP, mac net.HardwareAddr, leaseLen int) error {
	leaseLenDur := time.Duration(leaseLen) * time.Second
	newNode := NewLeaseNode(ip, mac, leaseLenDur, time.Now())
	c.LeasesCache.Put(newNode)

	database.LeaseIP(c.LeasesCache.db, newNode.ip, newNode.mac, newNode.leaseLen, newNode.leasedOn)

	return nil
}

func (c *Cache) Unlease(node *LeaseNode) {
	dbLease := &types.DatabaseLease{
		IP:       node.ip.String(),
		MAC:      node.mac.String(),
		LeasedOn: database.FormatTime(node.leasedOn),
		LeaseLen: int(node.leaseLen.Seconds()),
	}

	database.Unlease(c.LeasesCache.db, dbLease)
}

func (c *Cache) UnleaseIP(ip net.IP) {
	node := c.LeasesCache.IPGet(ip)
	c.Unlease(node)
}

func (c *Cache) UnleaseMAC(mac net.HardwareAddr) {
	node := c.LeasesCache.MACGet(mac)
	c.Unlease(node)
}

func (c *Cache) IsIPAvailable(ip net.IP) bool {
	return c.LeasesCache.IPGet(ip) == nil
}

func (c *Cache) IsMACLeased(mac net.HardwareAddr) net.IP {
	node := c.LeasesCache.MACGet(mac)
	if node == nil {
		return nil
	}

	return node.ip
}
