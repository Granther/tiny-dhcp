package cache

import (
	"fmt"
	"gdhcp/database"
	"net"
)

type ListNode struct {
	val		net.IP
	prev	*ListNode
	next	*ListNode
}

type AddrQueue struct {
	space		int
	left		*ListNode
	right		*ListNode
}

func NewListNode(val net.IP, prev *ListNode, next *ListNode) *ListNode {
	return &ListNode{
		val:	val,
		prev:	prev,
		next: 	next,
	}
}

func NewAddrQueue(max int) *AddrQueue {
	left := NewListNode(nil, nil, nil)
	right := NewListNode(nil, left, nil)
	left.next = right

	return &AddrQueue{
		space:		max,
		left: 		left,
		right:		right,
	}
}

func (q *AddrQueue) isEmpty() bool {
	return q.left.next == q.right
}

func (q *AddrQueue) isFull() bool {
	return q.space == 0
}

func (q *AddrQueue) Empty() {
	q.left.next = q.right
	q.left.prev = q.right
	q.right.prev = q.left
	q.right.next = q.left
}

func (q *AddrQueue) Front() net.IP {
	if q.isEmpty() {
		return nil
	}
	return q.left.next.val
}

func (q *AddrQueue) Rear() net.IP {
	if q.isEmpty() {
		return nil
	}
	return q.right.prev.val
}

func (q *AddrQueue) enQueue(val net.IP) bool {
	if q.isFull() {
		return false
	}
	newNode := NewListNode(val, q.right.prev, q.right)
	q.right.prev.next = newNode
	q.right.prev = newNode
	q.space -= 1

	return true
}

func (q *AddrQueue) deQueue() bool {
	if q.isEmpty() {
		return false
	}
	q.left.next = q.left.next.next
	q.left.next.prev = q.left
	q.space += 1

	return true
}

func (q *AddrQueue) RearToEnd() {
	node := q.left.next
	// Fix left
	q.left.next = node.next
	q.left.next.prev = q.left
	// Fix Node
	node.next = q.right
	node.prev = q.right.prev
	// Fix right
	q.right.prev.next = node
	q.right.prev = node
}

func (q *AddrQueue) PrintQueue() {
	for ptr := q.left.next; ptr != q.right; ptr = ptr.next {
		fmt.Println(ptr.val)
	}
}