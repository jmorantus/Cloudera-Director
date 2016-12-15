#!/bin/bash

#### Configurations ####

# DNS settings
NAMESERVER="10.5.0.24"
IP_ADDRESS=$(ip addr | grep eth0 -A2 | head -n3 | tail -n1 | awk -F'[/ ]+' '{print $3}')
PTR_RECORD=$(echo ${IP_ADDRESS} | awk -F . '{print $4"."$3"."$2"."$1".in-addr.arpa"}')

# AD domain controller
ADDC="morantusad.cloudera.morantus.com"

# Windows domain parameters
#PREWIN2K_HOSTNAME=$(echo ${IP_ADDRESS} | awk -F . '{print "director-jm"$4}')
PREWIN2K_HOSTNAME=director-jm
DOMAIN="CLOUDERA.MORANTUS.COM"
DNS_SUFFIX="cloudera.morantus.com"
COMPUTER_OU="ou=servers,ou=prod,ou=clusters,ou=hadoop,dc=CLOUDERA,dc=MORANTUS,dc=COM"
GROUP_OU_BASE="dc=CLOUDERA,dc=MORANTUS,dc=COM"
ADJOIN_USER="jmorantus"
ADJOIN_PASSWORD='Kerberos00!'
WORKGROUP="CLOUDERA"

#### SCRIPT START ####

# Set SELinux to permissive
setenforce 0

# Update DNS settings to point to the AD domain controller
sed -e 's/PEERDNS\=\"yes\"/PEERDNS\=\"no\"/' -i /etc/sysconfig/network-scripts/ifcfg-eth0
chattr -i /etc/resolv.conf
sed -e "s/search .*/search ${DNS_SUFFIX}/" -i /etc/resolv.conf
sed -e "s/nameserver .*/nameserver ${NAMESERVER}/" -i /etc/resolv.conf

# Fix a dependency issue (IPA and other things already installed)
yum erase -y libipa_hbac.x86_64

# Install base packages
yum install -y perl wget unzip krb5-workstation openldap-clients rng-tools oddjob oddjob-mkhomedir sssd samba-common adcli nscd ntp

# Enable and start rngd
echo 'EXTRAOPTIONS="-r /dev/urandom"' > /etc/sysconfig/rngd
chkconfig rngd on
service rngd start

# Enable and start ntpd
service ntpd start 
chkconfig ntpd on


## Setup hosts file
sed -e "s/^${IP_ADDRESS}.*//g" -i /etc/hosts
echo -e "${IP_ADDRESS}\t${PREWIN2K_HOSTNAME}.${DNS_SUFFIX}\t${PREWIN2K_HOSTNAME}" >> /etc/hosts

## Set hostname
hostname "${PREWIN2K_HOSTNAME}.${DNS_SUFFIX}"

## Setup Samba config
echo "[global]
   netbios name = ${PREWIN2K_HOSTNAME}
   workgroup = ${WORKGROUP}
   security = ADS
   realm = ${DOMAIN}
   encrypt passwords = yes
   kerberos method = secrets and keytab
   client ldap sasl wrapping = sign
" > /etc/samba/smb.conf

## Setup SSSD config
echo "[sssd]
config_file_version = 2
services = nss, pam
domains = ${DOMAIN}
debug_level = 0

[nss]
override_homedir = /home/%u
default_shell = /bin/bash
reconnection_retries = 3

[pam]
reconnection_retries = 3

[domain/${DOMAIN}]
debug_level = 0
enumerate = false
ignore_group_members = true
id_provider = ad
chpass_provider = ad
auth_provider = ad
access_provider = simple
ad_server = ${ADDC}
ldap_schema = ad
ldap_user_principal = nosuchattr
ldap_id_mapping = true
ldap_force_upper_case_realm = true
case_sensitive = false
krb5_realm = ${DOMAIN}
ldap_access_order = filter,expire
ldap_account_expire_policy = ad
cache_credentials = true
account_cache_expiration = 15
enum_cache_timeout = 120
entry_cache_nowait_percentage = 50
entry_cache_nowait_timeout = 28800
ldap_group_search_base = ${GROUP_OU_BASE}
ldap_sasl_authid = host/${PREWIN2K_HOSTNAME}.${DNS_SUFFIX}@${DOMAIN}
dyndns_update = true
dyndns_refresh_interval = 43200
dyndns_update_ptr = true
dyndns_ttl = 3600
" > /etc/sssd/sssd.conf

## Make sure sssd.conf has the right permissions or else SSSD won't start
chmod 600 /etc/sssd/sssd.conf

## Setup Kerberos client config
echo "[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 dns_lookup_realm = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 rdns = false
 default_realm = ${DOMAIN}
 default_ccache_name = KEYRING:persistent:%{uid}
 udp_preference_limit = 1

[realms]
 ${DOMAIN} = {
  kdc = ${ADDC}
  admin_server = ${ADDC}
 }

[domain_realm]
 .${DNS_SUFFIX} = ${DOMAIN}
 ${DNS_SUFFIX} = ${DOMAIN}
" > /etc/krb5.conf

## Setup nscd
mv /etc/nscd.conf /etc/nscd.conf.old
echo "#       logfile                 /var/log/nscd.log
#       threads                 4
#       max-threads             32
        server-user             nscd
#       stat-user               somebody
        debug-level             0
#       reload-count            5
        paranoia                no
#       restart-interval        3600

# Disabled for SSSD
        enable-cache            passwd          no
        enable-cache            group           no
        enable-cache            netgroup        no

        enable-cache            hosts           yes
        positive-time-to-live   hosts           3600
        negative-time-to-live   hosts           20
        suggested-size          hosts           211
        check-files             hosts           yes
        persistent              hosts           yes
        shared                  hosts           yes
        max-db-size             hosts           33554432

        enable-cache            services        yes
        positive-time-to-live   services        28800
        negative-time-to-live   services        20
        suggested-size          services        211
        check-files             services        yes
        persistent              services        yes
        shared                  services        yes
        max-db-size             services        33554432
" > /etc/nscd.conf

## Join the AD domain and create kerberos keytab to update DNS
net ads join createupn=host/${PREWIN2K_HOSTNAME}.${DNS_SUFFIX}@${DOMAIN} createcomputer=${COMPUTER_OU} -S ${ADDC} -U ${ADJOIN_USER}%${ADJOIN_PASSWORD}

rm -f /etc/krb5.keytab
net ads keytab create -S ${ADDC} -U ${ADJOIN_USER}%${ADJOIN_PASSWORD}

## Setup SSSD
authconfig --enablesssd --enablesssdauth --enablemkhomedir --update
service sssd restart

## Setup Dynamic DNS Updates. REPLACE WITH YOUR OWN PATH
sh /root/OS-bootstrap.sh

## Enable and start nscd
chkconfig nscd on
service nscd start
