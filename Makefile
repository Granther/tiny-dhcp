build:
	go build cmd/main.go

build_arm:
	env GOOS=linux GOARCH=arm64 go build cmd/main.go	

run: 
	go run cmd/main.go
