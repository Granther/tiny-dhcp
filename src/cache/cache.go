package cache

import (
	"gdhcp/database"
	"log/slog"
	"net"
)

type Cache struct {
	AddrPool    []string
	AddrQueue   *AddrQueue
	LeasesCache *LeasesCache
	PacketCache *PacketCache
}

func NewCache(packetCap int, packetTTL int, leasesMax int, queueMax int, addrPool []string) *Cache {
	return &Cache{
		AddrPool:    addrPool,
		AddrQueue:   NewAddrQueue(queueMax),
		LeasesCache: NewLeasesCache(leasesMax),
		PacketCache: NewPacketCache(packetCap, packetTTL),
	}
}

func (c *Cache) Init(num int) error {
	err := c.FillAddrs(num)
	return err
}

func (c *Cache) FillAddrs(num int) error {
	// While new addrs list < num
	// Generate addr from bottom of thing, if in cache or in queue, skip
	// else, add

	// Clear Queue, fuck it
	c.AddrQueue.Empty()

	var newAddrs []net.IP
	startIP := net.ParseIP(c.AddrPool[0]).To4()
	endIP := net.ParseIP(c.AddrPool[1]).To4()

	for ip := startIP; !ip.Equal(endIP) || len(newAddrs) < num; ip = database.IncrementIP(ip) {
		if c.LeasesCache.ipCache[&ip] != nil { // Doesnt exist in leases
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
