package cache

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"time"

	database "gdhcp/database"
)

type Cache struct {
	AddrPool    []string
	AddrQueue   *AddrQueue
	LeasesCache *LeasesCache
	PacketCache *PacketCache
}

func NewCache(packetCap int, packetTTL int, leasesMax int, queueMax int, addrPool []string) *Cache {
	slog.Debug("Creating new generat cache, and all children")

	return &Cache{
		AddrPool:    addrPool,
		AddrQueue:   NewAddrQueue(queueMax),
		LeasesCache: NewLeasesCache(leasesMax),
		PacketCache: NewPacketCache(packetCap, packetTTL),
	}
}

func (c *Cache) Init(db *sql.DB, num int) error {
	err := c.ReadLeasesFromDB(db)
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
			return fmt.Errorf("Unable to extract MAC from DatabaseLease: %v", err)
		}

		leasedOn, err := time.Parse("2006-01-02 15:04:05", lease.LeasedOn)
		if err != nil {
			return fmt.Errorf("Unable to parse str time from db to time.Time: %v", err)
		}

		ip := net.ParseIP(lease.IP)

		leaseNode := NewLeaseNode(ip, mac, time.Duration(lease.LeaseLen), leasedOn)
		c.LeasesCache.Put(leaseNode)
	}
}

func (c *Cache) FillQueue(num int) error {
	// While new addrs list < num
	// Generate addr from bottom of thing, if in cache or in queue, skip
	// else, add

	// Clear Queue, fuck it
	c.AddrQueue.Empty()

	var newAddrs []net.IP
	startIP := net.ParseIP(c.AddrPool[0])
	endIP := net.ParseIP(c.AddrPool[1])

	for ip := startIP; !ip.Equal(endIP) && len(newAddrs) < num; ip = database.IncrementIP(ip) {
		_, ok := c.LeasesCache.ipCache[&ip]
		if !ok { // Doesnt exist in leases
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
