package cache

import (
	"fmt"
	"net"
)

type ListNode struct {
	val		net.IP
	prev	*ListNode
	next	*ListNode
}

type CircularQueue struct {
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

func NewCirularQueue(max int) *CircularQueue {
	// Doubley linked, 2 dummy nodes linked to eachother
	left := NewListNode(nil, nil, nil)
	right := NewListNode(nil, left, nil)
	left.next = right

	return &CircularQueue{
		space:		max,
		left: 		left,
		right:		right,
	}
}

func (q *CircularQueue) isEmpty() bool {
	return q.left.next == q.right
}

func (q *CircularQueue) isFull() bool {
	return q.space == 0
}

func (q *CircularQueue) Front() net.IP {
	if q.isEmpty() {
		return nil
	}
	return q.left.next.val
}

func (q *CircularQueue) Rear() net.IP {
	if q.isEmpty() {
		return nil
	}
	return q.right.prev.val
}

func (q *CircularQueue) enQueue(val net.IP) bool {
	if q.isFull() {
		return false
	}
	newNode := NewListNode(val, q.right.prev, q.right)
	q.right.prev.next = newNode
	q.right.prev = newNode
	q.space -= 1

	return true
}

func (q *CircularQueue) deQueue() bool {
	if q.isEmpty() {
		return false
	}
	q.left.next = q.left.next.next
	q.left.next.prev = q.left
	q.space += 1

	return true
}

func (q *CircularQueue) RearToEnd() {
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

func (q *CircularQueue) PrintQueue() {
	for ptr := q.left.next; ptr != q.right; ptr = ptr.next {
		fmt.Println(ptr.val)
	}
}