#!/sbin/sh
#
# ADDOND_VERSION=2
#
# Before /system/addon.d/50-lineage.sh is executed in restore mode,
# the delivered /system/etc/hosts file of the upgraded ROM is saved
# as /system/etc/hosts.new
#

. /tmp/backuptool.functions

case "$1" in
  backup)
    # Stub
  ;;
  restore)
    # Save the delivered hosts file of the updated ROM
    cp -f $S/etc/hosts $S/etc/hosts.new
  ;;
  pre-backup)
    # Stub
  ;;
  post-backup)
    # Stub
  ;;
  pre-restore)
    # Stub
  ;;
  post-restore)
    # Stub
  ;;
esac
