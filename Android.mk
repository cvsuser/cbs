LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= kfifo.cpp cabox_service.cpp
LOCAL_SHARED_LIBRARIES := \
    libcutils liblog libutils


LOCAL_C_INCLUDES:= \
    $(TOP)/frameworks/native/include/ \

LOCAL_CFLAGS += -Wno-multichar -Wall -fpermissive -static
LOCAL_MODULE_TAGS := debug

LOCAL_MODULE := cbs
include $(BUILD_EXECUTABLE)

