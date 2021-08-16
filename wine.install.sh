#!/bin/bash

#instalar wine en Ubuntu 20.04--ejecutar como root
dpkg --add-architecture i386
cd Downloads

wget -qO- https://dl.winehq.org/wine-builds/winehq.key | sudo apt-key add -
apt-add-repository 'deb http://dl.winehq.org/wine-builds/ubuntu/ focal main'
apt-get install --install-recommends winehq-stable -y
apt-get install --install-recommends winehq-staging -y
wine --version
#wget http://www.extraputty.com/snapshots/Download/ExtraPuTTY-0.30-2016-04-04.zip
wget http://www.extraputty.com/snapshots/Download/ExtraPuTTY-0.30-2016-04-04-installer.exe
#Instalar ExtraPuTTY como si fuera Windows.

#para montar DAVWEB
apt-get update
apt install davfs2 -y
usermod -aG davfs2 framos
mkdir -p /home/framos/Cloud
#sudo mount -t davfs -o noexec https://ipdelservidor/remote.php/webdav/ /mnt/dav
#nano /etc/fstab
mkdir ~/.davfs2
cp  /etc/davfs2/secrets ~/.davfs2/secrets
chown framos:framos  ~/.davfs2/secrets
chmod 600 ~/.davfs2/secrets

#agregar al final del achivo secrets
#https://example.com/nextcloud/remote.php/dav/files/USERNAME/ <username> <password>
#or
#$PathToMountPoint $USERNAME $PASSWORD
#for example
#/home/user/nextcloud john 1234
/home/framos/Cloud framos framos11

#Add the mount information to /etc/fstab:
#https://example.com/nextcloud/remote.php/dav/files/USERNAME/ /home/<linux_username>/nextcloud davfs user,rw,auto 0 0
https://encoremsi.com/cloud/remote.php/dav/files/framos/ /home/framos/Cloud davfs framos,rw,auto 0 0

#agregar al final del archivo /etc/davfs2/davfs2.conf 
use_locks 0

#Test
mount ~/Cloud
#listo al reiniciar el quipo se montara los archivos en automatico (como no funciono automatico, agregue un tarea a cron)

@reboot mount ~/Cloudy

#install SSH Server
apt-get install openssh-server -y
systemctl enable sshd
systemctl start sshd

#Cambiar puerto al 2222
nano /etc/ssh/sshd_config



#Instalacion de HestiaCP
cd Downloads
wget https://raw.githubusercontent.com/hestiacp/hestiacp/release/install/hst-install.sh
bash hst-install.sh




