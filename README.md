<a id="readme-top"></a>
<br />
<h2 align="center"><h4>*tiny*</h4>-DHCP</h2>
  <p align="center">
    A cute, small, simple DHCP Server written from scratch (no DHCP packages) in Go
    <br />
  </p>
</div>

## About The Project
Its a small DHCP server, small as in:
* Minimal memory/disk footprint
* Fast startup, running & shutdown
* Utilizing Golang's core features for concurrency and speed

### Uses
Well, I, a 19 year old unemployed nerd wrote this. Although I am confident, it may have bugs that make mission critical deployments a problem. It wasn't written for environments with a high number of devices, running this at home is a great option

### Why?
- Mainly for the learning experience. Implementing a rock solid protocol from scratch while using Go has been a blast
- I also wanted to host a dedicated DHCP server in my homelab, only to realize there are not many homelab friendly projects that allow me to do this

## Installation
### Prerequisites
* An ARM or x86 machine with a network adapter (pretty much any computer)
* Golang xxx installed

### Building
1. Clone this repo down and enter root directory
```
git clone
cd tiny-dhcp
```
2. Build!
```
# For x86
make build

# For Arm (raspberry pi, etc)
make build_arm
```
