#!/bin/bash

#Variables
keytble_file=/etc/opendkim/KeyTable
SigningTable_file=/etc/opendkim/SigningTable
keys_dir=/etc/opendkim/keys

#ssh root@119.8.2.168 'bash -s' < /home/framos/scripts/framos/test.sh

#*Local
#*read -p "Nombre del DOMINIO que se firmara con DKIM, SPF, y DMARC > " dominio
#*echo $keytble  

#*Remoto
dominio=framos.ml

#* Diccionario de claves para cada DOMINIO
domainkey='mail._domainkey.'$dominio' '$dominio':mail:/etc/opendkim/keys/'$dominio'/mail.private'
#cat $keytble_file
#*Inserta el nuevo domainkey del DOMINIO en el archivo KeyTable
#echo $domainkey >> $keytble_file
#*Combrueba que este la nueva linea en el archivo
#cat $keytble_file


#*Definimos el diccionario de firmas, este se usa para asociar cada dirección de email con su dominio:
#cat $SigningTable_file
#echo
firma='*@'$dominio' mail._domainkey.'$dominio
#echo $firma >> $SigningTable_file
#*Combrueba que este la nueva linea en el archivo
#cat $SigningTable_file

#*Creamos las llaves públicas:
cd $keys_dir
#mkdir $dominio
cd $dominio
#pendkim-genkey -b 2048 -r -h rsa-sha256 -d $dominio -s mail -v
#*opendkim-genkey: generating private key
#*opendkim-genkey: private key written to mail.private
#*opendkim-genkey: extracting public key
#*opendkim-genkey: DNS TXT record written to mail.txt



#*Le damos permisos adecuados:
#chown -R opendkim:opendkim /etc/opendkim
#chmod -R go-rw /etc/opendkim/keys
#*ls -al $keys_dir

#*Reiniciamos Postfix y opendkim:
#/etc/init.d/postfix restart
#/etc/init.d/opendkim restart

#*Configuración DNS del dominio para agregar la llave de seguridad:
#more mail.txt

#*Creamos el registro TXT en el DNS como lo indica el código:
#*Tipo: TXT
#*Nombre: mail._domainkey
#*Contenido: 
#*v=DKIM1; h=sha256; s=email; k=rsa; t=y; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArHymhAN/YiXE3+16gsGY6itOY8X+fz8sy1STxWeTbtXNW0YAaKJeNTHtGkJ5Q/+reNFEXqFN3ghZ9gJOnkHs6YfKk7fREjm3jcUfTp0B466HHR5WZieg3r589UqqUso59UOSiCipMLyQzfehBkTtLL10yJxG1uYTSiujdpxl7q6UTeUkO+fSelIQtkjzN/mpj1VkVbG82AZG3D LUrHj8TJQW41eC3Iy7UdKJXxNNrH0jQUgH6WqX30adYShfIsFNKP0RvjtvzRxm8x7qWCSiL/y4dPMIK4+Tnpk6Uwyuiy5x/l8CS9LZihuz9ndcoHFPspvnXR3+JMDgddH6Uyj3IQIDAQAB


#*Nos fijamos que se difunda, y probamos el certificado. (si da un error es que algo esta mal, la difusion puede tardar)
#*DNS Checker mail._domainkey."dominio"
#opendkim-testkey -d $dominio -s mail -vvv
#*opendkim-testkey: using default configfile /etc/opendkim.conf
#*opendkim-testkey: checking key 'mail._domainkey.framos.ml'
#*opendkim-testkey: key not secure
#*opendkim-testkey: key OK

#*Prubar envio y validar en SCORE https://www.mailgenius.com/

#*Configurar SPF. (Enviado por...) ==> Solo se agrega registro TXT en el DNS
#*DNS.
#*Agregar un registro TXT con el nombre “mx” y el contenido del código: Tipo:TXT Nombre:@ TTL:Automatic Contenido:lo siguiente
#*Para un dominio en especifico:
v=spf1 a mx ip4:3.131.242.165 -all
#*Para todos los dominios:
v=spf1 mx -all
#*Combrobar en DNS Checker que este difundido y despues continuar


#*Configurar DMARC. (ES LA ULTIMA configuracion que se tiene que hacer)
#*Crear un registro TXT, con nombre _dmarc en el contenido:
v=DMARC1; p=quarantine; rua=mailto:admin@framos.ml
#*A esta direccion de email llegan los reportes de DMARC (correo del admin o webmaster)
