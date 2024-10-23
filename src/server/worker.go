package server

import (
	"fmt"
	"log/slog"
)

type WorkerHandler interface {
	Start()
	Stop()
}

// Exported interface to be used in Server struct
type WorkerPoolHandler interface {
	StartWorkers()
	Stop()
	SubmitJob(job JobHandler) error
}

type Worker struct {
	id         int
	jobChannel <-chan JobHandler // Recieve only channel for jobs
	quit       chan struct{}
}

type WorkerPool struct {
	numWorkers int
	jobChannel chan JobHandler // Bidirectional channel owned by the pool
	workers    []WorkerHandler
	quit       chan struct{}
}

func NewWorkerPool(numWorkers int) WorkerPoolHandler {
	return &WorkerPool{
		numWorkers: numWorkers,
		jobChannel: make(chan JobHandler, 1000), // Buffer size of 1000
		workers:    make([]WorkerHandler, 0, numWorkers),
		quit:       make(chan struct{}),
	}
}

func NewWorker(id int, jobChannel <-chan JobHandler) WorkerHandler {
	return &Worker{
		id:         id,
		jobChannel: jobChannel,
		quit:       make(chan struct{}),
	}
}

func (wp *WorkerPool) Stop() {
	close(wp.quit)
	for _, worker := range wp.workers {
		worker.Stop()
	}
}

func (w *Worker) Start() {
	go func() {
		for {
			select {
			case job := <-w.jobChannel:
				if err := job.Process(); err != nil {
					slog.Error("Error processing worker job", "error", err)
				}
			case <-w.quit:
				return
			}
		}
	}()
}

func (w *Worker) Stop() {
	close(w.quit)
}

func (wp *WorkerPool) StartWorkers() {
	for i := 0; i < wp.numWorkers; i++ {
		worker := NewWorker(i, wp.jobChannel)
		wp.workers = append(wp.workers, worker)
		worker.Start()
	}
}

func (wp *WorkerPool) SubmitJob(job JobHandler) error {
	select {
	case wp.jobChannel <- job:
		return nil
	default:
		return fmt.Errorf("unable to submit job, job queue is full")
	}
}
