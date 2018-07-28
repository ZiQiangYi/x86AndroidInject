LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := inject
LOCAL_SRC_FILES := inject.cpp
LOCAL_LDLIBS :=  -llog
LOCAL_ARM_MODE := thumb
LOCAL_CFLAGS += -fno-stack-protector -fvisibility=hidden

include $(BUILD_EXECUTABLE)
