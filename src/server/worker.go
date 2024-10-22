package server

import (
	"fmt"
	"gdhcp/config"
	"log/slog"
	"net"
)

type Job interface {
	Process() error
}

type Worker interface {
	Start()
	Stop()
}

type WorkerPool interface {
	StartWorkers(numWorkers int)
	Stop()
	SubmitJob(jon Job) error
}

type PacketJob struct {
	data       []byte
	clientAddr *net.UDPAddr
}

type defaultWorker struct {
	id         int
	jobChannel <-chan Job // Bidirectional channel owned by the pool
	workers    []Worker
	quit       chan struct{}
}

func (p PacketJob) Process() error {
	return nil
}

type WorkerInterface interface {
}

type WorkerManager struct {
}

func NewWorkerManager(config *config.Config) (WorkerInterface, error) {

}

func (w *WorkerManager) worker() {
	for job := range s.packetch {
		s.workerPool <- struct{}{}
		err := s.handleDHCPPacket(job.data)
		if err != nil {
			slog.Error(fmt.Sprintf("Error occured while handline dhcp packet: %v", err))
		}
		// Reads one item off the worker queue
		<-s.workerPool
	}
}
