#!/bin/bash

#Para poner IP ESTATICA
sudo nano -c /etc/network/interfaces

# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug enp0s3
#iface enp0s3 inet dhcp
# This is an autoconfigured IPv6 interface
#iface enp0s3 inet6 auto

# Static IP address
auto enp0s3
iface enp0s3 inet static
	address 192.168.1.20
        netmask 255.255.255.0
        network 192.168.1.0
        broadcast 192.168.1.255
        gateway 192.168.1.254

#para cambiar DNS
sudo nano -c /etc/resolv.conf

domain localdomain
search localdomain
nameserver 192.168.1.254
nameserver 8.8.8.8
nameserver 8.8.4.4

#para reiniciar Interface
ifdown enp0s3
ifup enp0s3