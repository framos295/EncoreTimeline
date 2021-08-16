#!/bin/bash
#Link Debian 10 (pagina oficial):
#https://cdimage.debian.org/debian-cd/current/amd64/iso-dvd/debian-10.9.0-amd64-DVD-1.iso
#https://cdimage.debian.org/debian-cd/current/amd64/iso-dvd/debian-10.10.0-amd64-DVD-1.iso



#vaciamos el .bashrc
cat /dev/null > .bashrc2

#Copiarmos le contenido el archivo de configuracion al .bashrc
#Despoues de hacer el cambio en el archovo reiniciamos con
source ~/.bashrc

#1.4.Conectando al servidor usando SSH.
#conectartse con llaves, despues de descargar la llane del servidor, entrar al directorio donde esta y cambiar permisos a 400
chmod 400 "LLAVE"
#conectarse al servidor con user admin y la IP del ervidor, en este caso 54.153.54.16

ssh -i "LLAVE" admin@54.153.54.16
ssh root@119.8.2.168 #huawei
#se puede generar otra KEY
ssh-keygen -t rsa -b 4096
#se confirma y opcional poner password que pedira cada vez que se conecta, si dejamos en blanco no pedira contrasena
#se guardan en:
/root/.ssh/id_rsa
cd /root/.ssh/
#NOTA: si se genera como admin entonces sera home/admin, de lo contrario solo dejara conectarse con root

#hacer copia de las llaves autorizadas
#cp -av /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bkp
cp /home/admin/.shh/
cd /admin/.ssh/
#cd /root/.ssh/
cp /home/admin/.ssh/authorized_keys /home/admin/.ssh/authorized_keys.bkp 
cat id_rsa.pub >> authorized_keys
#bajar el id-rsa al cliente con permisos 400
#y ya se podra conectar (revisar bien el id_rsa.pub ahi indica con que isuario se podra conectar)
ssh -i "LLAVE" admin@54.153.54.16
#huawei como root en directorio /home/framos/Documents/servidor_email/keys
ssh -i "huawei" root@119.8.2.168
#Huixtepec295

#1- Se abren los puertos necesarios en el router y el servidor despues se actuallizan reglas del firewall--comento Juan que no es necesaro hacerlo en el servidor pero si en el router claro
apt install ufw -y
ufw status verbose
#Con este comando enlistamos las aplicaciones
#ufw allow 80/tcp
ufw allow OpenSSH
#Ver info de la app
#ufw app info OpenSSH
ufw enable
ufw allow SMTP
#o se puede usar el numero de puerto (al usar el nombre del servicio es solo si nos aparece en la lista)
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 465/tcp
ufw allow 'Mail submission'
ufw allow IMAPS
ufw allow POP3S

#Limpiamos las reglas

iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X


#2.1. Actualizar servidor.
apt update -y && apt upgrade -y
apt install aptitude htop vim nmap -y
aptitude update

##
##  En las MV se tiene instalado nmap, y actualizado
##

#2.2.Instalar MySQL/MariaDB.
aptitude install mariadb-client mariadb-server

#2.3.Instalar Apache y PHP y NMAP para análisis de puertos.  (quitamos php-tcpdf  porque da error de instalacion, no es candidato)
#php-tcpdf si se instalo en AWS
aptitude install apache2 libapache2-mod-bw unzip zip build-essential php php-gd php-phpseclib php-pear php-zip php-xml php-readline php-mysql php-mbstring php-json php-gd php-curl php-common php-cli php-cgi php-bz2 libapache2-mod-php libpq5 php-pgsql php-sqlite3 php-pgsql php-sqlite3 php-imagick certbot python-certbot-apache php-tcpdf 

#adicional, instalar este paquete para que funcione el de abajo y saber el relase del SO
apt-get install lsb-release -y
lsb_release -d

#2.4.Instalar Postfix y Dovecot.
aptitude install postfix postfix-mysql dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql libsasl2-modules dovecot-pop3d mysqmail-postfix-logger dovecot-managesieved dovecot-sieve mailutils
#Al instalar postfix pideun DNS, hacer un ping al dominio y se onbserva el DNS
#pra AWS es: ec2-54-153-54-16.us-west-1.compute.amazonaws.com
#para huawei ecs-119-8-2-168.compute.hwclouds-dns.com
#pero aca se agrega el registro PTR en HUAWEI apuntando la EIP al dominio, se revisa con DNS Cheker y puede resultar el regitro del renglon de arriba o el nombre de dominio

#189.223.139.205.dsl.dyn.telnor.net
#187.250.182.241.dsl.dyn.telnor.net
#para cambiar el NDN en postfix:
#nano /etc/postfix/main.cf
#nano /etc/mailname

# hacer scaneo de los puertos nmap localhost
#nmap localhost

#se requieren crear los regitros A y MX en el DNS
#mx.trajearteoaxaca.com

#4.1.Configuración del servidor web. 
#Configuración de apache2
cd /etc/apache2/sites-available
#creamos el archivo de configuracion .conf
nano -c mx.trajearteoaxaca.com.conf

#ponemos el codigo dentro del archivo
<VirtualHost *:80>
    ServerName mx.trajearteoaxaca.com
    # Redirect permanent / https://mx.trajearteoaxaca.com
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    Customlog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName mx.trajearteoaxaca.com
    ServerAlias mx.trajearteoaxaca.com/
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    Customlog ${APACHE_LOG_DIR}/access.log combined

SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
</VirtualHost>
</IfModule>

#habilitamos el sitio
a2ensite mx.trajearteoaxaca.com.conf
# para deshabikliatr un sitio: a2dissite

#riniciamos apache2
/etc/init.d/apache2 restart

#4.2.Creación de los certificados de seguridad SSL/TLS.
certbot --apache
#ponemos mail
#A
#Y
#lejor dominio de l allista
#Luego nos dara 2 opciones,
#1. No redireccionar todo para https
#2. Redireccionar todas las consultas del sitio a través de https.
#elejimos 1 y editamos el archivo
nano -c mx.trajearteoaxaca.com.conf
#descomentamos
    # Redirect permanent / https://mx.trajearteoaxaca.com



#5.2.Configuración de adminer.
aptitude install adminer

#Ahora lo compilamos.
cd /usr/share/adminer/
php compile.php

#Copiaremos este archivo en el mismo directorio con el nombre solo de ​ adminer.php
cp adminer-4.7.1.php adminer.php

#Ahora creamos un alias en las configuraciones de apache para poder acceder.
echo "Alias /adminer.php /usr/share/adminer/adminer.php" | tee /etc/apache2/conf-available/adminer.conf

#Activamos el alias
a2enconf adminer.conf

#Reiniciamos el servicio de apache2
systemctl reload apache2
#y/o --> tambien
/etc/init.d/apache2 restart

#6.1.Crear usuario del servidor de email.
#es mejor crear diferentes usuarios, por ejemplo uno quesolo pueda leer la base de datos sin poder editar el contenido y otro que pudieraagregar datos pero solo alterar las claves
#mysql -u root -p
#usamos sin -p porque root no tiene password hasta el momento
mysql -u root
#Creamos el usuario mailuser:cursoemail
CREATE USER 'mailuser'@'localhost' IDENTIFIED BY 'cursoemail';

#Ahora le daremos todos los privilegios, solo para este curso.
GRANT ALL PRIVILEGES ON *.* TO 'mailuser'@'localhost' WITH GRANT OPTION;
flush privileges;
quit

#6.2.Crear base de datos y tablas con adminer.
#Base de datos.
#Nombre: mailserver
#Cotejamiento: utf8_general_ci
mysql -u root
CREATE DATABASE mailserver COLLATE 'utf8_general_ci';

USE mailserver;

CREATE TABLE virtual_aliases (
  id int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id int(11) NOT NULL,
  source varchar(100) NOT NULL,
  destination varchar(100) NOT NULL
) ENGINE='InnoDB';

CREATE TABLE virtual_domains (
  id int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name varchar(150) NOT NULL
) ENGINE='InnoDB';

CREATE TABLE virtual_users (
  id int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain_id int(11) NOT NULL,
  password varchar(106) NOT NULL,
  email varchar(100) NOT NULL,
  quota_rule varchar(10) NOT NULL,
  status_ int(2) NOT NULL DEFAULT '1'
) ENGINE='InnoDB';

quit

#6.3.Crear cuentas de email, claves, alias y dominios.
#Vamos a generar el hash para la contraseña
doveadm pw -s SHA512-CRYPT
#cursoemail
#{SHA512-CRYPT}
#$6$UmTcn06KNIM0EZbk$FZQrOj4m8RLq7yEMGNcYGLgwszHLiXroIW3IEYCLG022pn2HuO.WKeUEAKyd92tUHhvoWjo8Na6/by656a9JO0
mysql -u root
USE mailserver;

INSERT INTO `virtual_domains` (`name`) VALUES ('trajearteoaxaca.com');

#Ahora vamos a crear un email: otro@trajearteoaxaca.com
INSERT INTO `virtual_users` (`domain_id`, `password`, `email`, `quota_rule`, `status_`) VALUES ('1', '$6$UmTcn06KNIM0EZbk$FZQrOj4m8RLq7yEMGNcYGLgwszHLiXroIW3IEYCLG022pn2HuO.WKeUEAKyd92tUHhvoWjo8Na6/by656a9JO0', 'otro@trajearteoaxaca.com', '5M', '1');

#Ahora agregaremos un alias: webmaster@trajearteoaxaca.com ==> otro@trajearteoaxaca.com
INSERT INTO `virtual_aliases` (`domain_id`, `source`, `destination`) VALUES ('1', 'webmaster@trajearteoaxaca.com', 'otro@trajearteoaxaca.com');
quit
#revisar la BD y deben estar las BD mailserver


#7.2.Configuración de Postfix como MTA (Mail Agent Transfer o Agente detransferencia de correo).
#7.2.1.Hacer backup antes de iniciar la configuración.
cp -r /etc/postfix/ /etc/postfix.bkp

cd /etc/postfix/
#Documentación git Postfix:
#github.com/ibyteman/EmailServer

#7.2.2.Configuración del archivo /etc/postfix/main.cf
nano -c /etc/postfix/main.cf
#Sustituir contenido por el de GIT

#cambiamos los certificados correctos l 23 aprox
# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/mx.trajearteoaxaca.com/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/mx.trajearteoaxaca.com/privkey.pem
smtp_tls_CApath = /etc/letsencrypt/live/mx.trajearteoaxaca.com/cert.pem
smtpd_tls_CApath = /etc/letsencrypt/live/mx.trajearteoaxaca.com/cert.pem
smtpd_use_tls=yes

#cambiamos el DNS del servicor l 87 aprox
#myhostname = 187.250.182.241.dsl.dyn.telnor.net 
#AWS:
myhostname = ec2-54-153-54-16.us-west-1.compute.amazonaws.com
#HUAWEI>
myhostname = trajearteoaxaca.com


#7.2.3.Ahora vamos a configurar el archivo ​ master.cf (se usa todo el contenido del GIT)
nano -c /etc/postfix/master.cf

#7.2.4.Ahora vamos a configurar los archivos que postfix necesita para conectarse a la base de datos MariaDB, que ya hemos definido dentro del archivo main.cf.

nano -c /etc/postfix/mysql-virtual-mailbox-domains.cf
user = mailuser
password = cursoemail
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s'

nano -c /etc/postfix/mysql-virtual-mailbox-maps.cf
user = mailuser
password = cursoemail
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_users WHERE email='%s'

nano -c /etc/postfix/mysql-virtual-alias-maps.cf
user = mailuser
password = cursoemail
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s'

nano -c /etc/postfix/mysql-virtual-email2email.cf
user = mailuser
password = cursoemail
hosts = 127.0.0.1
dbname = mailserver
query = SELECT email FROM virtual_users WHERE email='%s'

#o lo puedo copiar de los descargados
cp /home/framos/EmailServer-byteman/postfix/mysql-virtual-mailbox-domains.cf mysql-virtual-mailbox-domains.cf
cp /home/framos/EmailServer-byteman/postfix/mysql-virtual-mailbox-maps.cf mysql-virtual-mailbox-maps.cf
cp /home/framos/EmailServer-byteman/postfix/mysql-virtual-alias-maps.cf mysql-virtual-alias-maps.cf
cp /home/framos/EmailServer-byteman/postfix/mysql-virtual-email2email.cf mysql-virtual-email2email.cf

#Con esto probamos el archivo de acceso a la ​ tabla de dominios. (resoltado=1)
postmap -q trajearteoaxaca.com mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
#Ahora la tabla de ​ direcciones de email.  (resoltado=1)
postmap -q otro@trajearteoaxaca.com mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf

#Primero reiniciamos postfix​ , si la respuesta es OK entonces continuamos.
/etc/init.d/postfix restart

#podemos revisar los puertos abiertos 
nmap localhost
#PORT     STATE SERVICE
#21/tcp   open  ftp
#22/tcp   open  ssh
#25/tcp   open  smtp
#80/tcp   open  http
#110/tcp  open  pop3
#143/tcp  open  imap
#443/tcp  open  https
#465/tcp  open  smtps
#587/tcp  open  submission
#993/tcp  open  imaps
#995/tcp  open  pop3s
#3306/tcp open  mysql

#revisar servicios
systemctl status postfix

#8.-Dovecot como MDA:
#Hacer backup de archivos antes de iniciar la configuración.
cd /etc/dovecot
cp -avr /etc/dovecot/ /etc/dovecot.bkp

#podemos revisar errores en archivo: /var/log/upstart/dovecot.log.

#Estructura de directorios de almacenamieto.
#cheamos la carpetas del primer usuario
mkdir -p /var/mail/vhosts/trajearteoaxaca.com

#Creamos el grupo y el usuario para controlar los archivos de email
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /var/mail

#Ahora cambiamos el usuario y grupo de todos los directorios donde se almacenarán los emails. Este cambio se hace de forma recursiva, y usaremos el usuario y grupo que acabamos de crear.
chown -R vmail:vmail /var/mail


#8.2.Configuración de archivos de dovecot. (todo de GIT)
mv dovecot.conf dovecot.conf.bkp
#cp /home/framos/EmailServer-byteman/dovecot/dovecot.conf dovecot.conf
nano -c /etc/dovecot/dovecot.conf

#todo el contenido de GIT
cd conf.d/
mv 10-logging.conf 10-logging.conf.bkp
#cp /home/framos/EmailServer-byteman/dovecot/10-logging.conf 10-logging.conf
nano -c /etc/dovecot/conf.d/10-logging.conf

#corregir linea 115 lo correcto de grupo es vmail
mv 10-mail.conf 10-mail.conf.bkp
#cp /home/framos/EmailServer-byteman/dovecot/10-mail.conf 10-mail.conf
nano -c /etc/dovecot/conf.d/10-mail.conf

#corregir linea 10 = yes
#ilnea 101 se agrega login al final de linea
#linea 122 puede funcionar #!include auth-system.conf.ext o descomentada
#se tiene que descomentar linea 123 !include auth-sql.conf.ext
mv 10-auth.conf 10-auth.conf.bkp 
#cp /home/framos/EmailServer-byteman/dovecot/10-auth.conf 10-auth.conf
nano -c /etc/dovecot/conf.d/10-auth.conf

#el archivo auth-sql-conf-ext esta corecto ya no se configura, en Debian viene ya OK

#lineas importantes 32,75,84,116,140,157
#todo el contenido de GIT con user delcurso, solo corregir la linea 144 falro la s en vhosts
cd ..
mv dovecot-sql.conf.ext dovecot-sql.conf.ext.bkp 
#cp /home/framos/EmailServer-byteman/dovecot/dovecot-sql.conf.ext dovecot-sql.conf.ext
nano -c /etc/dovecot/dovecot-sql.conf.ext

#todo el archivo del repo GIT
cd conf.d/
mv 10-master.conf 10-master.conf.bkp 
#cp /home/framos/EmailServer-byteman/dovecot/10-master.conf 10-master.conf
nano -c /etc/dovecot/conf.d/10-master.conf

#se cambia el dominio y comentan lineas 36 y 52
mv 10-ssl.conf 10-ssl.conf.bkp 
#cp /home/framos/EmailServer-byteman/dovecot/10-ssl.conf 10-ssl.conf
nano -c /etc/dovecot/conf.d/10-ssl.conf
# SSL/TLS support: yes, no, required. <doc/wiki/SSL.txt>
ssl = required
ssl_cert = </etc/letsencrypt/live/mx.trajearteoaxaca.com/fullchain.pem
ssl_key = </etc/letsencrypt/live/mx.trajearteoaxaca.com/privkey.pem
#comentar las lineas 52 y 36
# ssl_dh = </usr/share/dovecot/dh.pem
# ssl_client_ca_dir = /etc/ssl/certs

#Se usa todo el archivo
mv 15-mailboxes.conf  15-mailboxes.conf.bkp
#cp /home/framos/EmailServer-byteman/dovecot/15-mailboxes.conf 15-mailboxes.conf
nano -c /etc/dovecot/conf.d/15-mailboxes.conf


#Reglas de control y filtrado de correos. Dovecot tiene un complementollamado SIEVE que se encarga de esto, pero hay que configurarlo.

#todo el archivo del repo, checar linea 47
mv 15-lda.conf 15-lda.conf.bkp 
#cp /home/framos/EmailServer-byteman/dovecot/15-lda.conf 15-lda.conf
nano -c /etc/dovecot/conf.d/15-lda.conf

#Se cambia domino en la linea 26, y puedes cambiar el correo de l webmaster tambien
mv 20-lmtp.conf 20-lmtp.conf.bkp
#cp /home/framos/EmailServer-byteman/dovecot/20-lmtp.conf 20-lmtp.conf
nano -c /etc/dovecot/conf.d/20-lmtp.conf
postmaster_address = support@trajearteoaxaca.com

#todo el archivo de repo (lienes importantes 24,40,41,88)
mv 90-sieve.conf 90-sieve.conf.bkp 
#cp /home/framos/EmailServer-byteman/dovecot/90-sieve.conf 90-sieve.conf
nano -c /etc/dovecot/conf.d/90-sieve.conf

#Ahora creamos el directorio sieve dentro de dovecot.
mkdir /etc/dovecot/sieve
#Y creamos la regla que busca un encabezado llamado X-Spam-Level
nano -c /etc/dovecot/sieve/spamfilter.sieve
#Y pegamos dentro del archivo lo siguiente.
require ["fileinto"];
# rule:[SPAM]
if header :contains "X-Spam-Level" "*" {
fileinto "Junk";
}

#Hacemos cambio de de grupo de la carpeta sieve
cd ..
chown -R root:dovecot sieve/
#Reiniciar dovecot:
/etc/init.d/dovecot restart
#Consultar el estado del servicio:
systemctl status dovecot.service

#realizar un nmap y ver que desaparece el puerto 143
nmap localhost
#PORT     STATE SERVICE
#21/tcp   open  ftp
#22/tcp   open  ssh
#25/tcp   open  smtp
#80/tcp   open  http
#443/tcp  open  https
#465/tcp  open  smtps
#587/tcp  open  submission
#993/tcp  open  imaps
#995/tcp  open  pop3s
#3306/tcp open  mysql

#Realizar la prueba de recepcion de correos desde gmail
mail -f /var/mail/vhosts/trajearteoaxaca.com/otro
#root@debian:/etc/dovecot# mail -f /var/mail/vhosts/trajearteoaxaca.com/otro
#"/var/mail/vhosts/trajearteoaxaca.com/otro": 1 message 1 new
#>N   1 Fabio Fernando Ram                   59/3084  Prueba 1
#? 

#Eliminar el mensaje pendiente en cola.
postsuper -d <Number>
#Eliminar todos los mensajes pendientes en cola.
postsuper -d ALL
#Encolar de nuevo el mensaje.
postsuper -r <Number>
#Encolar de nuevo todos los mensajes.
postsuper -r ALL
#Mostrar todos los mensajes en cola.
postqueue -p
#Hacer flush de la cola de correo, e intentar enviar o recibir todos nuevamente.
postqueue -f


#9.-Filtro Anti-SPAM.
#9.1. SPAMASSASSIN. Instalando y configurando SPAMASSASSIN.
aptitude install spamassassin spamc
#crearemos el usuario spamd para spamc.
adduser spamd --disabled-login
#Vamos a arrancar el servicio de spamassassin siempre en el inicio del sistema.
systemctl enable spamassassin.service
#Aquí hacemos que actualice automáticamente todos los días sus reglas.
nano -c /etc/default/spamassassin
#Cambiamos el valor de CRON a 1. l-33
CRON=1

#HABILITAR el uso de las reglas aprendidas, esta configuración debe hacerse unas 2 semanas después de estar aprendiendo. ESTO SE HACE YA QUE ESTE FUNCIONANDO EL SERVIDOR EN SU TOTALIDAD
nano -c /etc/spamassassin/local.cf
#Agregamos la siguiente línea.
use_bayes_rules 1

#Para no nostrar el archivo adjunto de los mail spam, descomentar linea 18 se cmbia 1 por 0
nano -c /etc/spamassassin/local.cf
report_safe 0

#Iniciamos el filtro anti spam.
service spamassassin start

#Configurar postfix para usar un filtro de contenido.
#Editamos el archivo /etc/postfix/master.cf y descomentamos -o content_filter=spamassassin  (linea 12)
#Luego en el final del archivo agregar las siguientes líneas a continuación,nuevamente teniendo en cuenta que la segunda línea debe comenzar con espacio..
#spamassassin unix - n  n - - pipe
# user=spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f ${sender} ${recipient}
nano -c /etc/postfix/master.cf

#Ahora reiniciamos postfix.
service spamassassin start
postfix reload
/etc/init.d/postfix restart


#realizamos la puerba de encio de correo SPAM
#Contenido:
#XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

#dESPUES DE ENVIAR EL MAIL DESDE gMAIL
ll -a /var/mail/vhosts/trajearteoaxaca.com/otro/
#deben esta el directorio .Junk
#debe estar el mail en curl o new
more /var/mail/vhosts/trajearteoaxaca.com/otro/.Junk/new/1....

#Y vamos a comprobar que fue enviado al directorio de Junk o spam. Si todo está correcto vamos a ver una línea como la que está resaltada en verde. (ESTE COMANDO EN ESTE MOMENTO DA ERROR PERO SI MUESTRA EL SPAM)
#root@ip-172-31-33-158:# doveadm search -A mailbox Junk
#support@byteman.io 1a4ee92007202c60ac6c0000c15a0048 1

#Aquí vamos a automatizar la eliminación de los email spam después de 30 días se dejan comentadas por el momento
nano -c /etc/crontab
#30 23  * * *   root    doveadm expunge -A mailbox Junk savedbefore 30d
#* *    * * *   root    doveadm search -A mailbox Junk savedbefore 22h >> /root/cron.log

****************************************************************************************************************

#10.Webmail o interfaz web para usuarios:
#10.1.Roundcube y configuración
#Instalación de Roundcube
aptitude install roundcube roundcube-plugins
#pregunta si queremos ocnfigurar BD, decimos SI
#damos la contraseña segura (cursoemail)
#Configuración de apache para interfaz roundcube.
#Configurar el sitio en /etc/apache2/sites-available/
cd /etc/apache2/sites-available/
nano -c mail.trajearteoaxaca.com.conf

<VirtualHost *:80>
        ServerName      mail.trajearteoaxaca.com
        # Redirect permanent / https://mail.trajearteoaxaca.com
        ServerAdmin     webmaster@localhost
        DocumentRoot    /var/lib/roundcube
        ErrorLog        ${APACHE_LOG_DIR}/error.log
        Customlog       ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<IfModule mod_ssl.c>
<VirtualHost *:443>
        ServerName      mail.trajearteoaxaca.com
        ServerAlias     mail.trajearteoaxaca.com/
        ServerAdmin     webmaster@localhost
        DocumentRoot    /var/lib/roundcube
        ErrorLog        ${APACHE_LOG_DIR}/error.log
        Customlog       ${APACHE_LOG_DIR}/access.log combined
  SSLCertificateFile	/etc/ssl/certs/ssl-cert-snakeoil.pem
  SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
</VirtualHost>
</IfModule>

#Habilitar el site
a2ensite mail.trajearteoaxaca.com.conf
#Reiniciar apache.
/etc/init.d/apache2 restart

#Crear el certificado SSL/TLS.
certbot --apache
#1-NO redireccionamos
#Vamos a forzar el uso de SSL.
nano -c mail.trajearteoaxaca.com.conf
#Cambiamos.# Redirect permanent / https://mail.trajearteoaxaca.com
#Quitamos el comentario: Redirect permanent / https://mail.trajearteoaxaca.com
#Y reiniciamosapache.
/etc/init.d/apache2 restart

#se prueba y debemos entrar al login de rouncube con SSL



#creamos copia de carpeta roundcube
cp -avr /etc/roundcube/ /etc/roundcube.bkp

#Definimos el servidor donde se va a conectar, como localhost. 

#primero hacemos copia del archivo config.inic.php
cp -av /etc/roundcube/config.inc.php /etc/roundcube/config.inc.php.bkp
#Editamos el archivo:
nano -c /etc/roundcube/config.inc.php
#Y cambiamos:$config['default_host'] = '';+
#Por: $config['default_host'] = 'localhost';
#ahora ya no aparece el imput de servidor
#Aun no esta listo para iniciar sesión así que debemoseditar el archivo/etc/roundcube/config.inc.php
nano -c /etc/roundcube/config.inc.php

<?php

/*
+-----------------------------------------------------------------------+
| Local configuration for the Roundcube Webmail installation.           |
|                                                                       |
| This is a sample configuration file only containing the minimum       |
| setup required for a functional installation. Copy more options       |
| from defaults.inc.php to this file to override the defaults.          |
|                                                                       |
| This file is part of the Roundcube Webmail client                     |
| Copyright (C) 2005-2013, The Roundcube Dev Team                       |
|                                                                       |
| Licensed under the GNU General Public License version 3 or            |
| any later version with exceptions for skins & plugins.                |
| See the README file for a full license statement.                     |
+-----------------------------------------------------------------------+
*/

$config = array();

/* Do not set db_dsnw here, use dpkg-reconfigure roundcube-core to configure database ! */
include_once("/etc/roundcube/debian-db-roundcube.php");

// The IMAP host chosen to perform the log-in.
// Leave blank to show a textbox at login, give a list of hosts
// to display a pulldown menu or set one host as string.
// To use SSL/TLS connection, enter hostname with prefix ssl:// or tls://
// Supported replacement variables:
// %n - hostname ($_SERVER['SERVER_NAME'])
// %t - hostname without the first part
// %d - domain (http hostname $_SERVER['HTTP_HOST'] without the first part)
// %s - domain name after the '@' from e-mail address provided at login screen
// For example %n = mail.domain.tld, %t = domain.tld
//$config['default_host'] = '';
$config['default_host'] = 'ssl://mx.trajearteoaxaca.com';
$config['default_port'] = 993;
$config['imap_auth_type'] = 'LOGIN';

// SMTP server host (for sending mails).
// Enter hostname with prefix tls:// to use STARTTLS, or use
// prefix ssl:// to use the deprecated SSL over SMTP (aka SMTPS)
// Supported replacement variables:
// %h - user's IMAP hostname
// %n - hostname ($_SERVER['SERVER_NAME'])
// %t - hostname without the first part
// %d - domain (http hostname $_SERVER['HTTP_HOST'] without the first part)
// %z - IMAP domain (IMAP hostname without the first part)
// For example %n = mail.domain.tld, %t = domain.tld
//$config['smtp_server'] = 'localhost';
$config['smtp_server'] = 'tls://mx.trajearteoaxaca.com';
$config['smtp_port'] = 587;

// SMTP port (default is 25; use 587 for STARTTLS or 465 for the
// deprecated SSL over SMTP (aka SMTPS))
//$config['smtp_port'] = 25;

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// this key is used to encrypt the users imap password which is stored
// in the session record (and the client cookie if remember password is enabled).
// please provide a string of exactly 24 chars.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = '2P0w9QIi47DWO05BOO4kQxdi';

// List of active plugins (in plugins/ directory)
// Debian: install roundcube-plugins first to have any
//$config['plugins'] = array(
//);
// List of active plugins (in plugins/ directory)
$config['plugins'] = array(
	'virtuser_query',
	'additional_message_headers',
	'archive',
	'emoticons',
//	'help',
//	'hide_blockquote',
	'identity_select',
	'legacy_browser',
//	'managesieve',
	'markasjunk',
	'newmail_notifier',
	'new_user_dialog',
	'new_user_identity',
	'password',
	'rcguard',
	'show_additional_headers',
//	'subscriptions_option',
//	'userinfo',
	'vcard_attachments',
	'zipdownload',
//	'xskin',
   	'identicon',
//	'enigma',
	'dkimstatus'
);

// skin name: folder from skins/
$config['skin'] = 'larry';

// Disable spellchecking
// Debian: spellshecking needs additional packages to be installed, or calling external APIs
//         see defaults.inc.php for additional informations
$config['enable_spellcheck'] = false;
$config['smtp_auth_type'] = 'LOGIN';
$config['product_name'] = 'Byteman.io - Curso de email server Udemy';
$config['useragent'] = 'Roundcube Webmail';

$config['virtuser_query'] = "SELECT email FROM mailserver.virtual_users WHERE email = '%u'";



#Se pasa al punto 
#10.3.Cuotas de usuario.
#Editar /etc/dovecot/conf.d/90-quota.conf en el área Backends descomentar. (descomentar linea 71)
nano -c /etc/dovecot/conf.d/90-quota.conf

plugin {
  quota = maildir:User quota
}

#Editar /etc/dovecot/conf.d/10-mail.conf, agregar al final (el archivo del repo ya la tenia)
nano -c /etc/dovecot/conf.d/10-mail.conf
mail_plugins = $mail_plugins quota

#Editar /etc/dovecot/conf.d/20-imap.conf, agregar al final de la linea. (esta linea 94 esta dentro de unas llaves a diferencia de las 2 anteriores)
nano -c /etc/dovecot/conf.d/20-imap.conf
mail_plugins = $mail_plugins imap_quota

#Reiniciar dovecot:
/etc/init.d/dovecot restart
#hay que cerrar sesion y entrar nuevamente para ver los cambios de las cuotas de almacenamiento

#hacer prueba de envio con fotos para ver con cambia el % de almacenamiento
#ahora cambiamos la cuopta en la BD desde adminer y aumentamos la cantiad de megas

#10.2.Contraseña de usuario. (se hace despues del punto 10.3
nano -c /etc/roundcube/config.inc.php

#Agregamos el contenido del repo GIT password_plugin al final del archivo
$config['password_driver'] = 'sql';
$config['password_confirm_current'] = true;
$config['password_minimum_length'] = 6;
$config['password_require_nonalpha'] = true;
$config['password_log'] = false;
$config['password_login_exceptions'] = null;
$config['password_hosts'] = array('mx.trajearteoaxaca.com');
$config['password_force_save'] = true;
 
//SQL Driver options
$config['password__db_dsn'] = 'mysql://roundcube:@localhost/roundcube';
 
$config['password_query'] = 'UPDATE mailserver.virtual_users SET password=ENCRYPT(%p, CONCAT(\'$6$\',SUBSTRING((SHA(RAND())), -16))) WHERE email=%u LIMIT 1';
 
$config['enable_installer'] = false;
$config['htmleditor'] = 1;

#Y ahora le damos los permisos necesarios al usuario de roundcube para poder alterar el campo password dentro de la tabla de usuarios de la bases de datos de nuestro servidor de email.
#Si el usuario de roundcube no tiene los permisos nunca podrá alterar las contraseñas de los usuarios.
mysql -u root -p
GRANT SELECT (`email`), UPDATE (`password`) ON `mailserver`.`virtual_users` TO 'roundcube'@'localhost';
quit
#hora si ya podemos cambiar el password dentro de roundcube

#10.4.Reglas y Filtros del usuario.
#Agregamos el plugin managesieve. Si ya hiciste todos los pasos anteriores ya debes tener este plugin entre las configuraciones en el archivo /etc/roundcube/config.inc.php
nano -c /etc/roundcube/config.inc.php
#descomentar linea 93 aprox, managesieve

#necesitamos instalar php-net-sieve
aptitude install php-net-sieve

#Editamos el archivo /etc/dovecot/conf.d/20-managesieve.conf
nano -c /etc/dovecot/conf.d/20-managesieve.conf
#Buscamos y activamos (descomentamos) las siguientes opciones. (linea 6,11,12,13,22,25,29)
protocols = $protocols sieve
service managesieve-login {
  inet_listener sieve {
    port = 4190
  }
  service_count = 1
  process_min_avail = 1
} <- Asegurate de quitar el comentario!

#Reiniciamos dovecot.
/etc/init.d/dovecot restart

#Recuerda que debes habilitar el plugin de managesieve en el archivo de configuración de roundcube. linea 93 aproxomadamente, se descomenta
nano -c /etc/roundcube/config.inc.php

#Y vamos a la sección de configuración -> filtros. Y ahora nos aparece así.
# se pueden crear aca los filtros personalizados, hacemos pruebas y se va a SPAM correctamente


#11.Jaula contra ataques de fuerza bruta con Fail2ban   

#Instalación y configuración de Fail2ban.
aptitude install fail2ban
#Habilitamos el servicio de fail2ban.
/lib/systemd/systemd-sysv-install enable fail2ban
#Copiamos el archivo de configuración base a un archivo .local donde vamos a hacer las configuraciones.
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
#Editar el archivo /etc/fall2ban/jail.local y configurar los siguientes valores. (linea 91,147,138,229)
nano -c /etc/fail2ban/jail.local
backend = polling
mta = sendmail
destemail = otro@trajearteoaxaca.com
action = %(action_mwl)s

#Ahora iniciamos fail2ban.
fail2ban-client start
#y reiniciamos el servicio.
service fail2ban restart

#También podemos usar fail2ban para bloquear spammers que envían mensajes a grupos de email,
#Editar el archivo /etc/fail2ban/filter.d/postfix.conf
nano -c /etc/fail2ban/filter.d/postfix.conf
#Agregar esta línea justo debajo de failregex. linea 53
reject: RCPT from (.*)\[<HOST>\]: 554 5.7.1
#Editar el archivo /etc/fail2ban/jail.local
nano -c /etc/fail2ban/jail.local
#Y debajo de la sección [Postfix] lo configuramos como habilitado. linea 541
enabled = true
#Configurar el máximo de intentos fallidos antes de bloquearlo. linea 70
maxretry = 10
#HABILITAR PARA ROUNDCUBE. l-388
#Debajo de [roundcube-auth] agregamos.
enabled = true
#Configurar log.(comentar 391 y poner la sig)
logpath = /var/log/roundcube/errors

#Editar el archivo /etc/fail2ban/filter.d/roundcube-auth.conf.
nano -c /etc/fail2ban/filter.d/roundcube-auth.conf
#Ajustamos el parámetro failregex. (comentamos la que esta y ponemos esta) l-18 y 19
failregex = IMAP Error: (FAILED login|Login failed) for .*? from <HOST>


#Editar el archivo /etc/fail2ban/jail.local
nano -c /etc/fail2ban/jail.local
#Justo debajo de [dovecot] linea 586
enabled = true
#Reiniciamos el servicio.
service fail2ban reload

#PD: Aquí hay un par de comandos interesantes.
#Desbloquear manualmente un cliente.
fail2ban-client set dovecot unbanip 119.8.2.168
#Revisar de forma manual la cárcel de ownCloud.
fail2ban-client status roundcube-auth
fail2ban-client status dovecot
fail2ban-client status postfix


#12.Pruebas de envío de correo cifrado:
#12.1.1.Prueba del puerto 25 y configuraciones de envío.
apt install telnet

#Ahora vamos a probar conectarnos al servidor smtpde gmail, o cualquierotro servidor de email de la siguiente forma:
telnet smtp.gmail.com 25

#Nos debe dar una respuesta como esta:
#220 smtp.gmail.com ESMTP y8sm223127qtn.68 - gsmtp

#Dovecot.
#Editamos el archivo /conf.d/10-ssl.conf l-52 y 36
nano -c /etc/dovecot/conf.d/10-ssl.conf
#Como están ahora:
# ssl_dh = </usr/share/dovecot/dh.pem
# ssl_client_ca_dir = /etc/ssl/certs
#Como deben de verse:
ssl_dh = </usr/share/dovecot/dh.pem
ssl_client_ca_dir = /etc/ssl/certs

#Postfix.
#Editamos el archivo /etc/postfix/main.cf
nano -c /etc/postfix/main.cf
#Y comentamos la siguiente línea: l-45 o 44
#smtp_sasl_auth_enable = yes

###############################################################################################################
##########                                                                         ############################
##########           HAsta aca llegamos , si no tenemos el puerto 25 abierto       ############################
##########                                                                         ############################
###############################################################################################################
#con huawei pasamos este paso porque le 25 esta abierto

#12.1.2.Pruebas de envío de correo, análisis de logs y errores.
#Hacemos envio de pruebas desde servidor de pruebas a un correo de servidor de pruebas, desde otro@otro@trajearteoaxaca.com  a office@encoremsi.com 

#Ahora vamos a revisar los archivos logs
vim /var/log/mail.log
#Ahora voy con el segundo:
vim /var/log/mail.err

#Para que las horaas coincidan, en el log, hay que cambiar la zona horaria
#Ver zona horario
timedatectl
#verificar a donde apunta lu rura del enlace simbolico
ls -l /etc/localtime
#Cambiar la zona horaria en Debian
#enlistas las zonas horarias disponibles
timedatectl list-timezones
#correcta America/Los_Angeles
timedatectl set-timezone America/Los_Angeles
#verificamos
timedatectl
data

#Si llego el correo del punto 12.1.2 ahora mandarlo a uno de gmail.
#Llega como CIFRADO ESTANDAR
#Revisar el plugin de DKIM
nano -c /etc/roundcube/config.inc.php

#Agrgar correos a la base de datos
mysql -u root
USE mailserver;
#Ahora vamos a crear un email: soporte@trajearteoaxaca.com
INSERT INTO `virtual_users` (`domain_id`, `password`, `email`, `quota_rule`, `status_`) VALUES ('1', '$6$UmTcn06KNIM0EZbk$FZQrOj4m8RLq7yEMGNcYGLgwszHLiXroIW3IEYCLG022pn2HuO.WKeUEAKyd92tUHhvoWjo8Na6/by656a9JO0', 'soporte@trajearteoaxaca.com', '15M', '1');
quit

#revisar los directorios de /var/mail/vhosts/trajearteoaxaca.com/ solo debe estar otro
ll /var/mail/vhosts/trajearteoaxaca.com/
#despues de loguearte el roundcube se creara la carpeta del usuario
ll /var/mail/vhosts/trajearteoaxaca.com/
#ya aparece la carpeta del usuario

#realizar pruebas de envio al nuevo correo desde gmail

#ahora agregamos el nuevo dominio
#En el nuevo dominio agregar el registro MX mx.trajearteoaxaca.com, y revisar con DNSChecker y ya que este difundido seguirle
#agregamos el nuevo dominio a la BD
mysql -u root
USE mailserver;

INSERT INTO `virtual_domains` (`name`) VALUES ('framos.ml');

#Ahora vamos a crear un email: admin@framos.ml:cursoemail
INSERT INTO `virtual_users` (`domain_id`, `password`, `email`, `quota_rule`, `status_`) VALUES ('2', '$6$UmTcn06KNIM0EZbk$FZQrOj4m8RLq7yEMGNcYGLgwszHLiXroIW3IEYCLG022pn2HuO.WKeUEAKyd92tUHhvoWjo8Na6/by656a9JO0', 'admin@framos.ml', '15M', '1'); 
quit


#revisamos directorio de vhosts
ll /var/mail/vhosts/
#total 4
#drwxr-sr-x 4 vmail vmail 4096 Aug 13 22:47 trajearteoaxaca.com

#hacemos loguin en roundcube y revisar nuevamente, debe crear carpeta de dominio y de ususario
root@ecs-email:~# ll /var/mail/vhosts/
#total 8
#drwxr-sr-x 3 vmail vmail 4096 Aug 13 23:43 framos.ml
#drwxr-sr-x 4 vmail vmail 4096 Aug 13 22:47 trajearteoaxaca.com

#hacemos prueba de encio al nuevo correo deo segundo dominio, todo debe estar OK

#Agregar cuenta a app GMAIL
#Agregar cuentas
#Otro
#poner direccion de email
#Configuracion manua
#Tipo de cuenta IMAP
#poner contrasena
#Seguir
#servidor: mx.trajearteoaxaca.com
#Se podria usa un subdomino IMAP...., SMTP..., buscar en google como crear sertificado para todos los subdominios con letsencript en cerbot, ese se configuraria en dovecot
#Seguir
#Servidor SMTP  mx.trajearteoaxaca.com
#Seguir
#Seguir
#Nombre: xxxxx
#Seguir
#Ya debe entrar a Gmail con el correo del dominio dado
#Prueba de correo y verlo en gmail

Agregar cuenta a gestor de correos en Linux Thunderbird
#Email
#poner Nombre, Correo y password
#configuracion manual:

#INCOMING==>IMAP
#Server: mx.trajearteoaxaca.com
#Port: 993
#SSL: SSL/TLS
#Authentication: Normal password

#OUTGOING==>SMTP
#Server: mx.trajearteoaxaca.com
#Port: 465
#SSL: SSL/TLS
#Authentication: Normal password

#PROBAR++Re-test
#Done==> Entra a la cuenta

#15.FIRMAR correo saliente.
#15.1.Configurar DKIM.

#orden de configuracion DKIM, 

#Importante el Dominio Reverso rDNS
#Esta configuracion esta en main.cf linea 88 aprox
nano -c /etc/postfix/main.cf

#otro dato IMPORTANTE es el HOSTMANE del servidor /etc/hostname, que se usara en DKIM(sistema de llaves para verificar el email)==>firmara
more /etc/hostname
#ecs-email

#Lo primero instalar y configurar opendkim y opendkim-tools:
apt install opendkim opendkim-tools postfix-policyd-spf-python postfix-pcre

#Agregamos el usuario postfix al grupo opendkim:
adduser postfix opendkim
mkdir /var/spool/postfix/opendkim

#Editamos el archivo /etc/opendkim.conf, pero antes hacemos un respaldo del archivo:
cp -av /etc/opendkim.conf /etc/opendkim.conf.bkp

nano -c /etc/opendkim.conf
#Se agregan al inicio l-4
AutoRestart		Yes
AutoRestartRate		10/1h

# Log to syslog (la primera ya esta, se agregar las 2 siguientes l-9 y 10)
Syslog			yes
SyslogSuccess		Yes
LogWhy			Yes

#se cambia 2 l-13
UMask			002

#Descomentar linea-23  Canonicalization y dejarla como sigue, descomentar l-25(mode), cambiar por yes la l-26 o 27 (SubDomains)
Canonicalization	relaxed/simple
Mode			sv
SubDomains		yes

#comentar la l-41 Socket y poner la siguiente
Socket                    local:/var/spool/postfix/opendkim/opendkim.sock

#PidFile linea 50 ya esta OK
#agregar linea debajo de la anterior (algoritmo de llaves)
SignatureAlgorithm	rsa-sha256

#comentar OversignHeaders linea 59 aprox y poner las siguientes 2
SignHeaders                     From,Sender,To,CC,Subject,Message-Id,Date
OversignHeaders                 From,Sender,To,CC,Subject,Message-Id,Date

#TrustAnchorFile ya esta OK linea 83 aprox
#userID comentar la linea91 aprox UserID y poner la siguiente
UserID                opendkim:opendkim

#agregar las siguientes 4 lineas
ExternalIgnoreList	refile:/etc/opendkim/TrustedHosts
InternalHosts		refile:/etc/opendkim/TrustedHosts
KeyTable		/etc/opendkim/KeyTable
SigningTable		refile:/etc/opendkim/SigningTable

#cambiamos de user y grupo la carpeta opendkim
chown opendkim:postfix /var/spool/postfix/opendkim


#Editamos el archivo /etc/default/opendkim, comentamos l-12 y ponemos le SOCKET  siguiente
nano -c /etc/default/opendkim
#Usamos la siguiente configuración:
SOCKET="local:/var/spool/postfix/opendkim/opendkim.sock"


#Preparamos POSTFIX: descomentar l-170-173 y deben ser estas 4 lineas sigueintes
nano -c /etc/postfix/main.cf
milter_default_action = accept
milter_protocol = 6
smtpd_milters = local:opendkim/opendkim.sock
non_smtpd_milters = local:opendkim/opendkim.sock

#IMPORTANTE esta linea 44 apro #smtp_sasl_auth_enable = yes debe estar comentada

#Creamos los directorios:
mkdir /etc/opendkim
mkdir /etc/opendkim/keys
#Creamos los archivos:
#Definimos los host autorizados para firmar los correos, incluyendo el nombre del servidor.
#Nombre del hostname
#IP fija del servidor
#dominio
#subdomini
nano -c /etc/opendkim/TrustedHosts
127.0.0.1
localhost
ecs-email
119.8.2.168
trajearteoaxaca.com
mx.trajearteoaxaca.com

#Definimos el diccionario de claves, para informar la clave de cada dominio.
nano -c /etc/opendkim/KeyTable
mail._domainkey.trajearteoaxaca.com trajearteoaxaca.com:mail:/etc/opendkim/keys/trajearteoaxaca.com/mail.private

#Definimos el diccionario de firmas, este se usa para asociar cada dirección de email con su dominio:
nano -c /etc/opendkim/SigningTable
*@trajearteoaxaca.com mail._domainkey.trajearteoaxaca.com

#Creamos las llaves públicas:
cd /etc/opendkim/keys
mkdir trajearteoaxaca.com
cd trajearteoaxaca.com
opendkim-genkey -b 2048 -r -h rsa-sha256 -d trajearteoaxaca.com -s mail -v

#Aparecen estos dos archivos:
-rw------- 1 root root 1675 Apr 12 06:30 mail.private ==> llave privada
-rw------- 1 root root 500 Apr 12 06:30 mail.txt   ==> llave publica, se agrega registro en el; DNS como registro TXT
#Le damos permisos:
chown -R opendkim:opendkim /etc/opendkim
chmod -R go-rw /etc/opendkim/keys


#Reiniciamos Postfix y opendkim:
/etc/init.d/postfix restart
/etc/init.d/opendkim restart

#Configuración DNS del dominio para agregar la llave de seguridad:
more mail.txt
mail._domainkey	IN	TXT	( "v=DKIM1; h=rsa-sha256; k=rsa; s=email; "
	  "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuRAcumxOiGK8Ld47o5YOVdXeXkW+694YYWuzl+bx2BVOKo3+JsxceF7VpuvTxNaANGz1MD0jps1Dhz7462G+BlQV9aCsKmSRK5
WtrajTCBdDsAefoTJVVX/MHEcKK6MmqOBcD4My28B9/EM1EhQcr5jUak0kT4PGxmlIg8N5VELrfDdyNy1aJEDWSzGmPWxbhUOqVXum9PPY9H"
	  "lDVnFAIFa2jjj1KkiOF/d1R20dL1ZRAd8VdSqkAZb8vbNJfLumbwPYPqEDZdrFPsl8TzQR85ACPAFLHtqL0t2oST+sFWyHVurx20fRuM3P0VeXZn3aBghUnDJAXu4DCEgBCVb/KQIDAQAB" 
)  ; ----- DKIM key mail for trajearteoaxaca.com

#Creamos el registro TXT como lo indica el código:
Tipo: TXT
Nombre: mail._domainkey
Contenido: 
v=DKIM1; h=sha256; s=email; k=rsa; t=y; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuRAcumxOiGK8Ld47o5YOVdXeXkW+694YYWuzl+bx2BVOKo3+JsxceF7VpuvTxNaANGz1MD0jps1Dhz7462G+BlQV9aCsKmSRK5WtrajTCBdDsAefoTJVVX/MHEcKK6MmqOBcD4My28B9/EM1EhQcr5jUak0kT4PGxmlIg8N5VELrfDdyNy1aJEDWSzGmPWxbhUOqVXum9PPY9H lDVnFAIFa2jjj1KkiOF/d1R20dL1ZRAd8VdSqkAZb8vbNJfLumbwPYPqEDZdrFPsl8TzQR85ACPAFLHtqL0t2oST+sFWyHVurx20fRuM3P0VeXZn3aBghUnDJAXu4DCEgBCVb/KQIDAQAB

#Nos fijamos que se difunda, y probamos el certificado.
opendkim-testkey -d trajearteoaxaca.com -s mail -vvv
#opendkim-testkey: using default configfile /etc/opendkim.conf
#opendkim-testkey: checking key 'mail._domainkey.trajearteoaxaca.com'
#opendkim-testkey: key secure
#opendkim-testkey: key OK



#Si todo funciona entonces probamos usando esta pagina de prueba que analiza nuestro mensaje en busca de una firma DKIM.
https://www.mailgenius.com/

#copiamos la direccion que nos da la pagina y hacemos prueba de envio desde servidor email
#despues de enviarlo SEE YOUR SCORE
#dbe pasar el test de DKIM, si pasa hacer prueba e envio a GMAIL y debe aparecer firmado por...

#15.2.Configurar SPF. (Enviado por...)
#DNS.
#Agregar un registro TXT con el nombre “mx” y el contenido del código: Tipo:TXT Nombre:@ TTL:Automatic Contenido:lo siguiente
#Para un dominio en especifico:
v=spf1 a mx ip4:3.131.242.165 -all
#Para todos los dominios:
v=spf1 mx -all
#Combrobar en DNS Checker que este difundido y despues continuar

#POSTFIX.
#Editar el archivo /etc/postfix-policyd-spf-python/policyd-spf.conf  (comentar l-6 y7 y agregar las siguientes 2)
nano -c /etc/postfix-policyd-spf-python/policyd-spf.conf
HELO_reject = False
Mail_From_reject = False

#Editar el archivo master.cf de postfix: (descomentar l-130 y 131 referencte a politicas SPF)
nano -c /etc/postfix/master.cf
olicy-spf  unix  -       n       n       -       -     spawn
  user=policyd-spf argv=/usr/bin/policyd-spf

#Editar el archivo main.cf de postfix: (descomentar l-82 apro referente a policyd-sfp, para que no rechache el mail por si tarda mas de lo normal)
nano -c /etc/postfix/main.cf
policyd-spf_time_limit = 3600

#Reiniciar postfix:
/etc/init.d/postfix restart

#Y nuevamente probamos si la configuración es reconocida.
#Si todo funciona entonces probamos usando esta pagina de prueba que analiza nuestro mensaje en busca de una firma DKIM.
#https://www.mailgenius.com/
#Si es reconocida entonces enviamos un email para gmail y observamos que ahora nos muestra Enviado por: Byteman.io y ademas Firmado por: Byteman.io

#15.3.Configurar DMARC. (ES LA ULTIMA configuracion que se tiene que hacer)
#Crear un registro TXT, con nombre _dmarc en el contenido:
v=DMARC1; p=quarantine; rua=mailto:otro@trajearteoaxaca.com
#A esta direccion de email llegan los reportes de DMARC

#Probar todas las configuraciones.
#Si todo funciona entonces probamos usando esta página de prueba que analiza nuestro mensaje en busca de una firma DKIM.
#https://www.mailgenius.com/
#Y si todo va bien vamos a enviar un email a GMAIL! y debería de llegar firmado y con el nombre del remitente.

#16.Antivirus CLAMAV.
#16.1.Aplicaciones.

#Instalamos lo necesario, y durante si tienes un servidor pequeño no dudes en hacer la memoria swap (opcional).
#Memoria SWAP (Opcional):
#creamos el archivo swap (Solo si tienes un servidor micro con 512MB de RAM):
dd if=/dev/zero of=/swap bs=1024 count=2048000
#Le damos un sistema de fichero swap:
mkswap /swap
#Y activamos la memoria virtual:
swapon /swap

#Instalamos Antivirus (Mensajes entrada y salida son escaneados y marcados)
apt install amavisd-new -y
apt install arj bzip2 cabextract cpio rpm2cpio file gzip lhasa nomarch pax p7zip-full unzip zip lrzip lzip liblz4-tool lzop unrar-free

#Se sugiere dar un nombre en el archivo 05-node_id si fuese necesario
#vim /etc/amavis/conf.d/05-node_id
#$myhostname = "ec2-3-131-242-165.us-east-2.compute.amazonaws.com";

#Verificamos, iniciamos y habilitamos el servicio:
systemctl status amavis
systemctl start amavis
systemctl enable amavis


#Si tienes problemas para habilitarlo con ese último comando ( systemctl enable amavis ), y te aparecen estas dos líneas:
#amavis.service is not a native service, redirecting to systemd-sysv-install.
#Executing: /lib/systemd/systemd-sysv-install enable amavis
#Entonces utiliza este comando como te lo sugiere el sistema, este es un cambio de última hora que detecte después de subir la clase, por eso lo estoy actualizando aquí en el documento:
#/lib/systemd/systemd-sysv-install enable amavis

#Verificamos el puerto predeterminado:
netstat -lnpt | grep amavis
#También puedes ver la versión:
amavisd-new -V
#Reiniciamos amavis
systemctl restart amavis

#Vamos a editar main.cf de postfix.
nano -c /etc/postfix/main.cf
#Y agregamos:
# Amavis Antivirus
content_filter=smtp-amavis:[127.0.0.1]:10024
smtpd_proxy_options = speed_adjust

#Ahora editamos el archivo master.cf de postfix. (gregar el contenido de GIT Adicional amavis) **El 2 es el nuero de mensajes que puede analizar al mismo tiemo
nano -c /etc/postfix/master.cf

#Reiniciamos Postfix:
/etc/init.d/postfix restart

#16.2. Instalamos, configuramos e integramos amavis con clamAV.
apt install clamav clamav-daemon
#Verificamos el status de clamav-freshclam :
systemctl status clamav-freshclam
#(Si es que no inicia solo, hay qye dar un start y despues verificarlo)
#Verificamos el status, iniciamos y habilitamos en el inicio el demonio de ClamAV:
systemctl status clamav-daemon
#(muestra inactivo por ser la primera vez, entonces hacer lo siguiente)
systemctl start clamav-daemon
#(Se inicia el demonio)
systemctl enable clamav-daemon

#Editamos /etc/clamav/freshclam.conf para activar las actualizaciones.
nano -c /etc/clamav/freshclam.conf
#Y cambiamos la línea: l-26
DatabaseMirror db.local.clamav.net
#Por lo siguiente:
DatabaseMirror db.us.clamav.net

#Con esto le decimos que use los servidores de estados unidos.
#Y reiniciamos nuevamente:
service clamav-daemon start


#16.3.Aquí vamos a activar la verificación de virus de amavis y clamav:
nano -c /etc/amavis/conf.d/15-content_filter_mode
#Descomentamos las dos líneas: 13 y 14
@bypass_virus_checks_maps = (
\%bypass_virus_checks, \@bypass_virus_checks_acl, \$bypass_virus_checks_re);

#Agregamos clamav al grupo amavis y tambien al grupo clamav :
adduser clamav amavis
adduser amavis clamav
#Ahora reiniciamos los 3 de una vez:
systemctl restart clamav-daemon amavis postfix
#Consultamos los logs de amavis
journalctl -eu amavis


#Y ahora enviamos un email desde gmail y verificamos la siguiente línea:
X-Virus-Scanned: Debian amavisd-new at ec2-13-58-53-44.us-east-2.compute.amazonaws.com


#16.4. Vamos a analizar el rendimiento de amavis:
#Lo primero que debemos hacer es buscar esta linea: (debajo de use strict)
nano -c /etc/amavis/conf.d/50-user
#y agregamos esta otra linea:(asi analizara 4 procesos al mismo tiempo)
$max_servers = 4;

#Después editar el archivo master.cf y editar aquel número de 2 a 4 por ejemplo.vim
nano -c /etc/postfix/master.cf

#Con este comando vemos los procesos que tiene o puede ahcer
amavisd-nanny

#Reiniciamos Postfix:
/etc/init.d/postfix restart

#Reiniciamos Amavis:
/etc/init.d/amavis restart

#checamos procesos y debern ser 4
amavisd-nanny

#revisar el demonio de clamav y si aparece en rojo con el me saje
#  Process: 12967 ExecStartPre=/bin/mkdir /run/clamav (code=exited, status=1/FAILURE)
#es porque no puede crear /run/clamav que ya existe, la solucion, eliminar el directorio
rm -rf /run/clamav
#reinicioamos clamav
systemctl restart clamav-daemon
#Verificamos status y ya debe estar sin errores
systemctl status clamav-daemon

#Reiniciamos Avavis y checamos log
/etc/init.d/amavis restart
journalctl -eu amavis