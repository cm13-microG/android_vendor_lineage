#!/sbin/sh
#
# ADDOND_VERSION=2
#
# After /system/addon.d/50-lineage.sh is executed in restore mode,
# the chosen behavior of the user whether to restore the hosts file
# or not is executed as per below comments
#

. /tmp/backuptool.functions

case "$1" in
  backup)
    # Stub
  ;;
  restore)
    # Depending if the hosts file should be restored or not,
    # the following will be the end result:
    # No backup/restore:
    #   hosts     => new delivered hosts file from updated ROM
    #   hosts.bak => previous hosts file
    # DO the backup/restore:
    #   hosts     => previous hosts file
    #   hosts.new => new delivered hosts file from updated ROM (created by 49-hosts.sh)
    if [ -f /data/user_de/0/com.android.settings/files/.hosts.backup ]; then
        rm $S/etc/hosts.bak
    else
        # rename hosts files
        rm $S/etc/hosts.bak
        mv $S/etc/hosts $S/etc/hosts.bak
        mv $S/etc/hosts.new $S/etc/hosts
    fi
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
