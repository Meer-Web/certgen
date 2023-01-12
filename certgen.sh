#!/bin/bash
########################################
# Author: F. Bischof (frank@meer-web.nl)
# Version: 1.4.2
# Date: 12-01-2022
########################################
ENCRYPTION="sha256"
BITS="rsa:2048"

function create_csr {
	if [ "${CONFIG}" != "" ]
	then
		openssl req -utf8 -nodes -${ENCRYPTION} -newkey ${BITS} -keyout ${DOMAIN}.key -out ${DOMAIN}.csr -config ${CONFIG_FILE} -extensions 'req_ext'
	else
		openssl req -utf8 -nodes -${ENCRYPTION} -newkey ${BITS} -keyout ${DOMAIN}.key -out ${DOMAIN}.csr
	fi
	echo "CSR ${DOMAIN}.csr created!"
}

function create_ssc {
	echo -en "How many years should it be valid: "; read YEARSVALID
	YEARSVALID=$(($YEARSVALID * 365))
	openssl req -x509 -nodes -days ${YEARSVALID} -newkey ${BITS} -keyout ${DOMAIN}.key -out ${DOMAIN}.crt -${ENCRYPTION}
	echo "Self Signed Certificate generated!"
}

function create_pfx {
	echo -en "Domain certificate path: "; read DOMAIN_CERT
	echo -en "Domain key path: "; read DOMAIN_KEY
	echo -en "Intermediate certificate path (optional): "; read INT_CERT
	if [ "${INT_CERT}" != "" ];
	then
		echo -en "Root certificate path: "; read ROOT_CERT
		cat ${INT_CERT} ${ROOT_CERT} > bundle-ca.crt; BUNDLE_CERT="bundle-ca.crt"
		openssl pkcs12 -export -in ${DOMAIN_CERT} -out ${DOMAIN}.pfx -inkey ${DOMAIN_KEY} -certfile ${BUNDLE_CERT}
	else
		openssl pkcs12 -export -in ${DOMAIN_CERT} -out ${DOMAIN}.pfx -inkey ${DOMAIN_KEY}
	fi
	echo "File ${DOMAIN}.pfx created!"
}

function extract_pfx {
	echo -en "PFX path: "; read PFX_CERT
	openssl pkcs12 -in ${PFX_CERT} -nocerts -out ${DOMAIN}.key -nodes
	openssl pkcs12 -in ${PFX_CERT} -nokeys -out ${DOMAIN}.crt
	echo "Files ${DOMAIN}.key and ${DOMAIN}.crt created from PFX"
}

function remove_pw {
	echo -en "Domain key path (optional): "; read DOMAIN_KEY
	openssl rsa -in ${DOMAIN_KEY} -out decrypted-${DOMAIN_KEY}
	echo "File decrypted-${DOMAIN_KEY} created!"
}

function create_all {
	echo -en "Domain certificate path: "; read DOMAIN_CERT
	echo -en "Domain key path (optional): "; read DOMAIN_KEY
	echo -en "Intermediate certificate path: "; read INT_CERT
	echo -en "Root certificate path: "; read ROOT_CERT
	# Create PEM
	if [ "${DOMAIN_KEY}" != "" ]
	then
		touch ${DOMAIN}.pem
		cat ${DOMAIN_KEY} > ${DOMAIN}.pem
		cat ${DOMAIN_CERT} >> ${DOMAIN}.pem
		cat ${INT_CERT} >> ${DOMAIN}.pem
		cat ${ROOT_CERT} >> ${DOMAIN}.pem
		echo "${DOMAIN}.pem (key, domain, intermediate, root) created"
	fi
	# Create BUNDLE-CA
	touch bundle-ca.crt
	cat ${INT_CERT} >> bundle-ca.crt
	cat ${ROOT_CERT} >> bundle-ca.crt
	echo "bundle-ca created (intermediate, root)"
	# Create domain bundle
	touch bundle.crt
	cat ${DOMAIN_CERT} >> bundle.crt
	cat ${INT_CERT} >> bundle.crt
	cat ${ROOT_CERT} >> bundle.crt
	echo "bundle.crt (domain, intermediate, root) created"


}

function decode_csr {
	echo -en "CSR path: "; read CSR_PATH
	openssl req -in ${CSR_PATH} -noout -text
}

function decode_crt {
	echo -en "CRT path: "; read CRT_PATH
	openssl x509 -in ${CRT_PATH} -text -noout
}

function match_crtkey {
	echo -en "CRT path: "; read CRT_PATH
	echo -en "KEY path: "; read KEY_PATH
	CRT_HASH="`openssl x509 -in ${CRT_PATH} -pubkey -noout -outform pem | sha256sum`"
	KEY_HASH="`openssl pkey -in ${KEY_PATH} -pubout -outform pem | sha256sum`"
	if [ "${CRT_HASH}" == "${KEY_HASH}" ]
	then
		echo -e "\nCertificate and key matching"
	else
		echo -e "\nCertificate and key are NOT matching!"
	fi
}

if [ "$1" == '--help' ];
then
	echo "Usage: $0 [domain.tld] [config]"
	exit 0
fi

if [ "$1" == '' ]
then
	echo -en "Domain: "
	read DOMAIN
fi

DOMAIN=$1
CONFIG_FILE=$2
# Show options menu
echo "1. Create self signed certificate"
echo "2. Create CSR";
echo "3. Create PFX file"
echo "4. Extract PFX to CRT/KEY"
echo "5. Create CA-Bundle and PEM files"
echo "6. Remove password from KEY file"
echo "7. Decode CSR"
echo "8. Decode CRT"
echo "9. Match CRT/KEY"
echo -en "Option: "; read OPTION

case ${OPTION} in
	1) create_ssc ;;
	2) create_csr ;;
	3) create_pfx ;;
	4) extract_pfx ;;
	5) create_all ;;
	6) remove_pw ;;
	7) decode_csr ;;
	8) decode_crt ;;
	9) match_crtkey ;;
	*) echo "Invalid option, exiting!"; exit 2;;
esac
exit 0
