#
# Service to activate / deactivate iptables block script
#
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE:= z_iptables
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := z_iptables.sh
LOCAL_INIT_RC := z_iptables.rc
include $(BUILD_PREBUILT)
