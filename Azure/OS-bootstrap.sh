#!/bin/sh

#
# This script will bootstrap these OSes:
#   - CentOS 6.7
#   - CentOS 7.2
#   - RHEL 6.7
#   - RHEL 7.2
#
# Notes and notible differences between OSes:
#   - CentOS 6.7 and RHEL 6.7 use dhclient
#   - CentOS 7.2 and RHEL 7.2 use NetworkManager
#


#
# Functions
#

# writing dhclient-exit-hooks is the same for CentOS 6.7 and RHEL 6.7
# function not indented so EOF works
dhclient_67()
{
# dhclient-exit-hooks explained in dhclient-script man page: http://linux.die.net/man/8/dhclient-script
# cat a here-doc represenation of the hooks to the appropriate file
cat > /etc/dhcp/dhclient-exit-hooks <<"EOF"
#!/bin/bash
printf "\ndhclient-exit-hooks running...\n\treason:%s\n\tinterface:%s\n" "${reason:?}" "${interface:?}"
# only execute on the primary nic
if [ "$interface" != "eth0" ]
then
    exit 0;
fi
# when we have a new IP, perform nsupdate
if [ "$reason" = BOUND ] || [ "$reason" = RENEW ] ||
[ "$reason" = REBIND ] || [ "$reason" = REBOOT ]
then
    printf "\tnew_ip_address:%s\n" "${new_ip_address:?}"
    host=$(hostname -s)
    domain=$(hostname | cut -d'.' -f2- -s)
    domain=${domain:='cdh-cluster.internal'} # REPLACE-ME If no hostname is provided, use cdh-cluster.internal
    IFS='.' read -ra ipparts <<< "$new_ip_address"
    ptrrec="$(printf %s "$new_ip_address." | tac -s.)in-addr.arpa"
    nsupdatecmds=$(mktemp -t nsupdate.XXXXXXXXXX)
    resolvconfupdate=$(mktemp -t resolvconfupdate.XXXXXXXXXX)
    echo updating resolv.conf
    grep -iv "search" /etc/resolv.conf > "$resolvconfupdate"
    echo "search $domain" >> "$resolvconfupdate"
    cat "$resolvconfupdate" > /etc/resolv.conf
    echo "Attempting to register $host.$domain and $ptrrec"
    {
        echo "update delete $host.$domain a"
        echo "update add $host.$domain 600 a $new_ip_address"
        echo "send"
        echo "update delete $ptrrec ptr"
        echo "update add $ptrrec 600 ptr $host.$domain"
        echo "send"
    } > "$nsupdatecmds"
    nsupdate "$nsupdatecmds"
fi
#done
exit 0;
EOF
chmod 755 /etc/dhcp/dhclient-exit-hooks
service network restart
}


centos_67()
{
    echo "CentOS 6.7"

    # execute the CentOS 6.7 / RHEL 6.7 dhclient-exit-hooks setup
    dhclient_67
}


rhel_67()
{
    echo "RHEL 6.7"

    # rewrite SELINUX config to disabled and turn off enforcement
    sed -i.bak "s/^SELINUX=.*$/SELINUX=disabled/" /etc/selinux/config
    setenforce 0
    # stop firewall and disable
    service iptables stop
    chkconfig iptables off
    # update config to disable IPv6 and disable
    echo "# Disable IPv6" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1

    # execute the CentOS 6.7 / RHEL 6.7 dhclient-exit-hooks setup
    dhclient_67
}

# writing network manager hooks is the same for CentOS 7.2 and RHEL 7.2
# function not indented so EOF works
networkmanager_72()
{
# Centos 7.2 and RHEL 7.2 uses NetworkManager. Add a script to be automatically invoked when interface comes up.
cat > /etc/NetworkManager/dispatcher.d/12-register-dns <<"EOF"
#!/bin/bash
# NetworkManager Dispatch script
# Deployed by Cloudera Director Bootstrap
#
# Expected arguments:
#    $1 - interface
#    $2 - action
#
# See for info: http://linux.die.net/man/8/networkmanager
# Register A and PTR records when interface comes up
# only execute on the primary nic
if [ "$1" != "eth0" || "$2" != "up" ]
then
    exit 0;
fi
# when we have a new IP, perform nsupdate
new_ip_address="$DHCP4_IP_ADDRESS"
host=$(hostname -s)
domain=$(hostname | cut -d'.' -f2- -s)
domain=${domain:='cloudera.morantus.com'} # REPLACE-ME If no hostname is provided, use cdh-cluster.internal
IFS='.' read -ra ipparts <<< "$new_ip_address"
ptrrec="$(printf %s "$new_ip_address." | tac -s.)in-addr.arpa"
nsupdatecmds=$(mktemp -t nsupdate.XXXXXXXXXX)
resolvconfupdate=$(mktemp -t resolvconfupdate.XXXXXXXXXX)
echo updating resolv.conf
grep -iv "search" /etc/resolv.conf > "$resolvconfupdate"
echo "search $domain" >> "$resolvconfupdate"
echo "nameserver 10.5.0.24" >> "$resolvconfupdate" # REPLACE-ME added nameserver for AD DDNS
cat "$resolvconfupdate" > /etc/resolv.conf
princ="host/$host.$domain"			# Added to get kerberos principal
kinit -kt /etc/krb5.keytab "$princ"		# Added to get kerberos ticket needed for secure AD DDNS update
echo "Attempting to register $host.$domain and $ptrrec"
{
    echo "update delete $host.$domain a"
    echo "update add $host.$domain 600 a $new_ip_address"
    echo "send"
    echo "update delete $ptrrec ptr"
    echo "update add $ptrrec 600 ptr $host.$domain"
    echo "send"
} > "$nsupdatecmds"
nsupdate -g "$nsupdatecmds"  # Added -g for secure AD DDNS update
exit 0;
EOF
chmod 755 /etc/NetworkManager/dispatcher.d/12-register-dns
service network restart

#### Configurations ####
# DNS settings
NAMESERVER="10.5.0.24"
IP_ADDRESS=$(ip addr | grep eth0 -A2 | head -n3 | tail -n1 | awk -F'[/ ]+' '{print $3}')
PTR_RECORD=$(echo ${IP_ADDRESS} | awk -F . '{print $4"."$3"."$2"."$1".in-addr.arpa"}')

# AD domain controller
ADDC="morantusad.cloudera.morantus.com"

# Windows domain parameters
PREWIN2K_HOSTNAME=$(echo ${IP_ADDRESS} | awk -F . '{print "cdh-cluster"$4}')
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
sh /home/azuredirectoradmin/config/OS-bootstrap.sh

## Enable and start nscd
chkconfig nscd on
service nscd start

#Install Java 8
yum remove --assumeyes *openjdk*
rpm -ivh "http://archive.cloudera.com/director/redhat/7/x86_64/director/2.2.0/RPMS/x86_64/jdk-8u60-linux-x64.rpm"

#Install MySQL JDBC Driver
wget http://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-5.1.39.tar.gz -O /tmp/mysql-connector-java-5.1.39.tar.gz
tar zxvf /tmp/mysql-connector-java-5.1.39.tar.gz -C /tmp/
mkdir -p /usr/share/java/
cp /tmp/mysql-connector-java-5.1.39/mysql-connector-java-5.1.39-bin.jar /usr/share/java/
rm /usr/share/java/mysql-connector-java.jar
ln -s /usr/share/java/mysql-connector-java-5.1.39-bin.jar /usr/share/java/mysql-connector-java.jar

}


centos_72()
{
    echo "CentOS 7.2"

    # execute the CentOS 7.2 / RHEL 7.2 network manager setup
    networkmanager_72
}

rhel_72()
{
    echo "RHEL 7.2"

    # rewrite SELINUX config to disable and turn off enforcement
    sed -i.bak "s/^SELINUX=.*$/SELINUX=disabled/" /etc/selinux/config
    setenforce 0
    # stop firewall and disable
    systemctl stop iptables
    systemctl iptables off
    # RHEL 7.x uses firewalld
    systemctl stop firewalld
    systemctl disable firewalld
    # Disable tuned so it does not overwrite sysctl.conf
    service tuned stop
    systemctl disable tuned
    # Disable chrony so it does not conflict with ntpd installed by Director
    systemctl stop chronyd
    systemctl disable chronyd
    # update config to disable IPv6 and disable
    echo "# Disable IPv6" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    # swappniess is set by Director in /etc/sysctl.conf
    # Poke sysctl to have it pickup the config change.
    sysctl -p

    # execute the CentOS 7.2 / RHEL 7.2 network manager setup
    networkmanager_72
}



#
# Main workflow
#

# ensure user is root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root."
    exit 1
fi

# find the OS and release
os=""
release=""

# if it's there, use lsb_release
rpm -q redhat-lsb
if [ $? -eq 0 ]; then
    os=$(lsb_release -si)
    release=$(lsb_release -sr)

# if lsb_release isn't installed, use /etc/redhat-release
else
    grep  "CentOS.* 6\.7" /etc/redhat-release
    if [ $? -eq 0 ]; then
        os="CentOS"
        release="6.7"
    fi

    grep "CentOS.* 7\.2" /etc/redhat-release
    if [ $? -eq 0 ]; then
        os="CentOS"
        release="7.2"
    fi

    grep "Red Hat Enterprise Linux Server release 6.7" /etc/redhat-release
    if [ $? -eq 0 ]; then
        os="RedHatEnterpriseServer"
        release="6.7"
    fi

    grep "Red Hat Enterprise Linux Server release 7.2" /etc/redhat-release
    if [ $? -eq 0 ]; then
        os="RedHatEnterpriseServer"
        release="7.2"
    fi
fi

echo "OS: $os $release"

# select the OS and run the appropriate setup script
not_supported_msg="OS $os $release is not supported."
if [ "$os" = "CentOS" ]; then
    if [ "$release" = "6.7" ]; then
        centos_67
    elif [ "$release" = "7.2" ]; then
        centos_72
    else
        echo not_supported_msg
        exit 1
    fi

elif [ "$os" = "RedHatEnterpriseServer" ]; then
    if [ "$release" = "6.7" ]; then
        rhel_67
    elif [ "$release" = "7.2" ]; then
        rhel_72
    else
        echo not_supported_msg
        exit 1
    fi
else
    echo not_supported_msg
    exit 1
fi

