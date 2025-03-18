# syntax=docker/dockerfile:1

FROM golang:1.21.13

RUN apt update && apt upgrade -y && apt install libpcap-dev -y

WORKDIR /gdhcp

COPY src ./

RUN go mod download

COPY . .

RUN go build -o main .

CMD [ "./main" ]

EXPOSE 67