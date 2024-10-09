# syntax=docker/dockerfile:1

# Copy public key
# git clone from ssh
# git checkout
# change workdir to that of git repo

FROM golang:1.21.11

RUN apt update && apt upgrade -y && apt install nano git ssh -y 

RUN git clone https://github.com/Granther/gdhcp.git
RUN ls
WORKDIR gdhcp
RUN git checkout go-dev

RUN go mod download

EXPOSE 67
EXPOSE 22


# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/engine/reference/builder/#copy
# COPY *.go ./