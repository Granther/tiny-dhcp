package cache

import (
	"time"
	"fmt"
	"log/slog"
)

type CacheNode struct {
	created		time.Time
	key			string
	val			interface{}
}

type PacketCache struct {
	cap		int
	cache	map[string]*CacheNode
	ttl 	time.Duration
} 

func NewPacketCache(cap int, ttl time.Duration) *PacketCache {
	slog.Debug("Creating new packet cache")

	cache := make(map[string]*CacheNode)

	return &PacketCache{
		cap:		cap,
		ttl:		ttl,
		cache:		cache,
	}
}

func (p *PacketCache) NewCacheNode(key string, val interface{}, created time.Time) *CacheNode {
	return &CacheNode{
		key:		key,
		val:		val,
		created:	created,
	}
}

func (p *PacketCache) Set(key string, val interface{}) error {
	if len(p.cache) >= p.cap {
		return fmt.Errorf("Packet cache capacity is full")
	}
	newNode := p.NewCacheNode(key, val, time.Now())
	p.cache[key] = newNode

	return nil
}

func (p *PacketCache) Get(key string) (interface{}, error) {
	node, ok := p.cache[key]
	if ok {
		return node.val, nil
	}
	return nil, nil
}

func (p *PacketCache) Remove(key string) {
	delete(p.cache, key)
}

func (p *PacketCache) Clean() {
	for key, node := range p.cache {
		if time.Since(node.created) > p.ttl {
			fmt.Println("Cleaning node")
			p.Remove(key)
		}
	}
}