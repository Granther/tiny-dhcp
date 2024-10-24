package worker

import (
	"fmt"
)

type JobHandler interface {
	Process() error
}

type PacketJob struct {
	data    []byte
	jobFunc func([]byte) error
}

func NewPacketJob(data []byte, jobFunc func([]byte) error) JobHandler {
	return &PacketJob{
		data:    data,
		jobFunc: jobFunc,
	}
}

func (p *PacketJob) Process() error {
	err := p.jobFunc(p.data)
	if err != nil {
		return fmt.Errorf("failure in processing packet data: %w", err)
	}
	return nil
}
