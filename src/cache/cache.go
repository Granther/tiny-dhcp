package cache

import (
	"time"
	"fmt"
	"log/slog"

	"github.com/google/gopacket/layers"
)

type CacheNode struct {
	created		time.Time
	key			string
	val			*layers.DHCPv4
}

type PacketCache struct {
	cap		int
	cache	map[string]*CacheNode
	ttl 	time.Duration
} 

func NewPacketCache(cap int, ttl int) *PacketCache {
	slog.Debug("Creating new packet cache", "ttl", ttl, "cap", cap)
	ttlDur := time.Duration(time.Second * time.Duration(ttl))

	cache := make(map[string]*CacheNode)

	return &PacketCache{
		cap:		cap,
		ttl:		ttlDur,
		cache:		cache,
	}
}

func (p *PacketCache) NewCacheNode(key string, val *layers.DHCPv4, created time.Time) *CacheNode {
	return &CacheNode{
		key:		key,
		val:		val,
		created:	created,
	}
}

func (p *PacketCache) Set(key string, val *layers.DHCPv4) error {
	if len(p.cache) >= p.cap {
		return fmt.Errorf("Packet cache capacity is full")
	}
	newNode := p.NewCacheNode(key, val, time.Now())
	p.cache[key] = newNode

	slog.Debug("Set item in cache", "key", key)

	return nil
}

func (p *PacketCache) Get(key string) *layers.DHCPv4 {
	node, ok := p.cache[key]
	if ok {
		return node.val
	}
	return nil
}

func (p *PacketCache) Remove(key string) {
	delete(p.cache, key)
}

func (p *PacketCache) Clean() {
	for key, node := range p.cache {
		if time.Since(node.created) > p.ttl {
			slog.Debug("Cleaning node", "xid", key)
			p.Remove(key)
		}
	}
}

func (p *PacketCache) CleanJob(frequency int) {
	freqTime := time.Duration(time.Second * time.Duration(frequency))

	for {
		time.Sleep(freqTime)
		slog.Debug("Cleaning cache...", "freq", freqTime)
		p.Clean()
	}
}