package cache

import (
	"time"
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

}

func (p *PacketCache) NewCacheNode(key string, val interface{}, created time.Time) *CacheNode {
	return node := &CacheNode{
		key:		key,
		val:		val,
		created:	created,
	}
}

func (p *PacketCache) Set(key string, val interface{}) error {
	
}

func (p *PacketCache) Get(key string) (interface{}, error) {

}