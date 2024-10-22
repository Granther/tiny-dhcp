package server

type PacketManager struct {
	workerPool	chan struct{}
	packetch
}

func NewPacketManager() (*PacketManager, error) {

}