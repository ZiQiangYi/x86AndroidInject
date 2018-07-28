LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := attach
LOCAL_SRC_FILES := Attach.cpp	
LOCAL_LDLIBS :=  -llog
LOCAL_ARM_MODE := thumb
LOCAL_CFLAGS += #-O1			#-fvisibility=hidden #-fno-stack-protector
   
include $(BUILD_SHARED_LIBRARY)
