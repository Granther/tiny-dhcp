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
	slog.Debug("Creating new generat cache, and all children")
	
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
	startIP := net.ParseIP(c.AddrPool[0])
	endIP := net.ParseIP(c.AddrPool[1])

	slog.Debug(startIP.String(), "Endf", endIP.String())

	for ip := startIP; !ip.Equal(endIP) && len(newAddrs) >= num; ip = database.IncrementIP(ip) {
		_, ok := c.LeasesCache.ipCache[&ip]
		if  !ok { // Doesnt exist in leases
			slog.Debug("IP does not exist in leases cache, appending to new addrs", "ip", ip.String())
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
