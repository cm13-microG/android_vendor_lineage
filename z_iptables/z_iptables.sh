#!/system/bin/sh

##
## IPTABLES / oem_out Custom Firewall Script for Android
##

# Variables, pointers to binaries
IPTABLES=/system/bin/iptables
IP6TABLES=/system/bin/ip6tables

##
## List of allowed apps to still connect to Google
##
list_apps() {
cat <<EOF
com.android.captiveportallogin
com.android.providers.downloads
com.aurora.store
com.github.yeriomin.yalpstore
com.google.android.gms
com.netflix.mediaclient
com.vonglasow.michael.satstat
org.freeandroidtools.safetynettest
org.microg.gms.droidguard
org.schabi.newpipe
EOF
}

##
## Create IP(6)TABLES return statement for the Google exception
## (only if respective app from exception list is installed)
##
jump_app() {
APP_DIR="/data/data/$1"
if [ -d "$APP_DIR" ]; then
  APP_UID=`stat -c %u "$APP_DIR"`
  $IPTABLES -A 'oem_out' -m owner --uid-owner $APP_UID -j RETURN
  $IP6TABLES -A 'oem_out' -m owner --uid-owner $APP_UID -j RETURN
fi
}

##
## IPv4: Check, whether the specified chain in table 'nat' exists
##
ip4_n_chain_exists() {
  $IPTABLES -t nat -n --list "$1" >/dev/null 2>&1
}

##
## IPv4: Check, whether the specified OUTPUT rule in table 'nat' exists
##
ip4_n_outrl_exists() {
  $IPTABLES -t nat -C OUTPUT -j "$1" >/dev/null 2>&1
}

##
## IPv4: Redirect DNS requests (port 53), except for VPN
##
ip4_set_dns() {
  $IPTABLES -t nat -A "$1" ! -o tun+ -p udp --dport 53 -j DNAT --to-destination "$2":53
  $IPTABLES -t nat -A "$1" ! -o tun+ -p tcp --dport 53 -j DNAT --to-destination "$2":53
}

##
## IPv6: Check, whether the specified chain in table 'nat' exists
##
ip6_n_chain_exists() {
  $IP6TABLES -t nat -n --list "$1" >/dev/null 2>&1
}

##
## IPv6: Check, whether the specified OUTPUT rule in table 'nat' exists
##
ip6_n_outrl_exists() {
  $IP6TABLES -t nat -C OUTPUT -j "$1" >/dev/null 2>&1
}

##
## IPv6: Redirect DNS requests (port 53), except for VPN
##
ip6_set_dns() {
  $IP6TABLES -t nat -A "$1" ! -o tun+ -p udp --dport 53 -j DNAT --to-destination ["$2"]:53
  $IP6TABLES -t nat -A "$1" ! -o tun+ -p tcp --dport 53 -j DNAT --to-destination ["$2"]:53
}

##
## Initialize and redirect DNS requests, if set accordingly
##
init_dns() {
# create/initialize the 'cust_dns' chains, if they do not exist, yet
ip4_n_chain_exists 'cust_dns' || $IPTABLES -t nat -N 'cust_dns'
ip4_n_outrl_exists 'cust_dns' || $IPTABLES -t nat -A OUTPUT -j 'cust_dns'
ip6_n_chain_exists 'cust_dns' || $IP6TABLES -t nat -N 'cust_dns'
ip6_n_outrl_exists 'cust_dns' || $IP6TABLES -t nat -A OUTPUT -j 'cust_dns'
# Flush the 'cust_dns' chains
$IPTABLES -t nat -F 'cust_dns'
$IP6TABLES -t nat -F 'cust_dns'
# Get DNS properties
PROP_DNS=$( getprop persist.privacy.iptab_dns_switch )
PROP_IP4=$( getprop persist.privacy.iptab_dns_srvip4 )
PROP_IP6=$( getprop persist.privacy.iptab_dns_srvip6 )
# if custom DNS is specified, set it
if [ "$1" == "1" ]; then
    [ -n "$PROP_IP4" ] && ip4_set_dns 'cust_dns' $PROP_IP4
    [ -n "$PROP_IP6" ] && ip6_set_dns 'cust_dns' $PROP_IP6
fi
# Set property, if not yet set
if [ "$PROP_DNS" != "$1" ]; then
    setprop persist.privacy.iptab_dns_switch $1
fi
}

##
## Flush OWN roles only
##
flush_oem() {
$IPTABLES -F 'oem_out'
$IP6TABLES -F 'oem_out'
}

##
## Own rules to block
##
do_block() {
# Reject outgoing IPv6 traffic to Facebook (w/o exception)
$IP6TABLES -A 'oem_out' -d 2620:0:1c00::/40 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2a03:2880::/32 -j REJECT --reject-with icmp6-port-unreachable
# Reject outgoing IPv4 traffic to Facebook (w/o exception)
$IPTABLES -A 'oem_out' -d 31.13.24.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 31.13.64.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 45.64.40.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 66.220.144.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 69.63.176.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 69.171.224.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 74.119.76.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 103.4.96.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 129.134.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 157.240.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 173.252.64.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 179.60.192.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 185.60.216.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 204.15.20.0/22 -j REJECT --reject-with icmp-port-unreachable

# Shoot Google exceptions (app list)
list_apps | while read APP; do
  jump_app "$APP"
done
# Further exception for GPS (Test only)
$IPTABLES -A 'oem_out' -m owner --uid-owner 1021 -j RETURN

# Block outgoing IPv6 traffic to Google
$IP6TABLES -A 'oem_out' -d 2001:4860::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2401:fa00::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2404:6800::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2600:1900::/28 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2605:ef80::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2607:f8b0::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2620:0:1000::/40 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2620:120:e000::/40 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2620:15c::/36 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2800:3f0::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2a00:1450::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2a00:79e0::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2a03:ace0::/32 -j REJECT --reject-with icmp6-port-unreachable
$IP6TABLES -A 'oem_out' -d 2c0f:fb50::/32 -j REJECT --reject-with icmp6-port-unreachable
# Block outgoing IPv4 traffic to Google
$IPTABLES -A 'oem_out' -d 8.8.4.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 8.8.8.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 8.34.208.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 8.35.192.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 23.236.48.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 23.251.128.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.184.0.0/13 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.192.0.0/13 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.200.0.0/14 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.204.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.220.0.0/14 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.224.0.0/12 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 35.240.0.0/13 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 41.222.150.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.9.224.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.9.227.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.9.228.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.9.232.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.9.240.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.15.113.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.15.114.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.15.116.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.15.120.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.15.124.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.15.126.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 64.233.160.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 66.102.0.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 66.249.64.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 70.32.128.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 72.14.192.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 74.114.24.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 74.125.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 89.207.224.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 89.207.231.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 103.86.148.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.132.0.0/14 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.154.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.196.0.0/14 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.237.160.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.237.164.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.237.172.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.237.174.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 104.237.188.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 107.167.160.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 107.178.192.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 108.59.80.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 108.170.192.0/18 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 108.177.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 130.211.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.22.64.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.22.80.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.22.84.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.22.86.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.22.88.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.22.116.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.22.120.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.22.128.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 136.22.159.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 142.250.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 146.148.0.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 159.192.27.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 162.216.148.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 162.222.176.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 172.102.8.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 172.110.32.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 172.217.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 172.253.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 173.194.0.0/16 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 173.255.112.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 176.126.58.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 185.25.28.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 185.150.148.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 185.225.248.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 192.104.160.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 192.158.28.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 192.178.0.0/15 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 194.122.80.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 194.122.82.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 199.192.112.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 199.223.232.0/21 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 207.223.160.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.65.152.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.65.155.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.68.108.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.81.188.0/22 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.226.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.228.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.233.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.234.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.236.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.242.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.244.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.246.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.249.0/24 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.250.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 208.117.252.0/23 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 209.85.128.0/17 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 209.107.176.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 216.58.192.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 216.73.80.0/20 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 216.239.32.0/19 -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A 'oem_out' -d 216.252.220.0/22 -j REJECT --reject-with icmp-port-unreachable
}

##
## If executed manually via command line, the system properties need
## to be set as well
##
set_prop() {
  PROP_STATE=$( getprop persist.privacy.iptab_blk )
  if [ "$PROP_STATE" != "$1" ]; then
      setprop persist.privacy.iptab_blk $1
  fi
}

##
## Main run
##
case "$1" in
  dns_on) init_dns 1
    ;;

  dns_off) init_dns 0
    ;;

  set)  flush_oem
        do_block
        set_prop 1
    ;;
  flush) flush_oem
         set_prop 0
    ;;
esac

