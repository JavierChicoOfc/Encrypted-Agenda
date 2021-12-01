#!/bin/bash

# en raíz del proyecto

mkdir A AC1
cd AC1
mkdir privado crls solicitudes nuevoscerts
touch index.txt
echo '01' > serial
# asegurarse de que openssl_AC1.cnf está en AC1/ (md5 del archivo: 5085be6402ff1ec8ac28fc3182775afe) *nota1
openssl req -x509 -newkey rsa:2048 -days 360 -keyout AC1privateKey.key -out ac1cert.pem -outform PEM -config openssl_AC1.cnf
# passphrase = pepe

cd ../A
openssl req -newkey rsa:2048 -keyout AprivateKey.key -out AcertRequest.csr
# passphrase = pepe
# resto: US, texas, houston, pepetaco, pepetacolog, pepepepe, pepe@pepe.com, challenge password: pepe, pepego
openssl rsa -in AprivateKey.key  -pubout > ApublicKey.pem
cp AcertRequest.csr ../AC1/solicitudes/
cd ../AC1
openssl ca -config openssl_AC1.cnf -out Acertificate.pem -in solicitudes/AcertRequest.csr
# Using configuration from openssl_AC1.cnf
# Enter pass phrase for ./privado/AC1privateKey.key: pepe     <--------- pepe es la passphrase
# contestar 'y' a todo

# ver el nuevo certificado de A firmado por AC1:
openssl x509 -in nuevoscerts/01.pem -text -noout
cp nuevoscerts/01.pem ../A/Acertificate.pem
cd ../A
# ver el certificado de A firmado por AC1:
openssl x509 -in Acertificate.pem -text -noout


# *nota1: si no coinciden:
# eliminar línea de RANDFILE al principio del documento (debajo de HOME)
# 36: dir		= .		# Where everything is kept
# 49: private_key	= $dir/privado/AC1privateKey.key# The private key
# 101: default_keyfile 	= ./privado/AC1privateKey.key
