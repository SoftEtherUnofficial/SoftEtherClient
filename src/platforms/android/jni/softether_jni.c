/**
 * SoftEther VPN - Android JNI Wrapper
 * 
 * JNI bindings for unified mobile VPN FFI (ffi.h)
 * Maps Java/Kotlin calls to platform-agnostic C API
 * 
 * Package: com.softether.vpn
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>
#include "../../../include/ffi.h"  // Unified FFI

#define LOG_TAG "SoftEtherJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ============================================================================
// Helper Functions
// ============================================================================

static const char* getStringUTF(JNIEnv* env, jstring jstr) {
    if (jstr == NULL) return NULL;
    return (*env)->GetStringUTFChars(env, jstr, NULL);
}

static void releaseStringUTF(JNIEnv* env, jstring jstr, const char* cstr) {
    if (cstr != NULL) {
        (*env)->ReleaseStringUTFChars(env, jstr, cstr);
    }
}

// ============================================================================
// JNI Exports - Initialization
// ============================================================================

JNIEXPORT jint JNICALL
Java_com_softether_vpn_MobileVpn_init(JNIEnv* env, jclass clazz) {
    LOGI("Initializing mobile VPN library");
    return mobile_vpn_init();
}

JNIEXPORT void JNICALL
Java_com_softether_vpn_MobileVpn_cleanup(JNIEnv* env, jclass clazz) {
    LOGI("Cleaning up mobile VPN library");
    mobile_vpn_cleanup();
}

// ============================================================================
// JNI Exports - VPN Lifecycle
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_softether_vpn_MobileVpn_create(JNIEnv* env, jclass clazz, jobject config) {
    LOGI("Creating VPN handle");
    
    // Get VpnConfig class
    jclass configClass = (*env)->GetObjectClass(env, config);
    
    // Get field IDs
    jfieldID serverField = (*env)->GetFieldID(env, configClass, "server", "Ljava/lang/String;");
    jfieldID portField = (*env)->GetFieldID(env, configClass, "port", "I");
    jfieldID hubField = (*env)->GetFieldID(env, configClass, "hub", "Ljava/lang/String;");
    jfieldID usernameField = (*env)->GetFieldID(env, configClass, "username", "Ljava/lang/String;");
    jfieldID passwordHashField = (*env)->GetFieldID(env, configClass, "passwordHash", "Ljava/lang/String;");
    jfieldID useEncryptField = (*env)->GetFieldID(env, configClass, "useEncrypt", "Z");
    jfieldID useCompressField = (*env)->GetFieldID(env, configClass, "useCompress", "Z");
    
    // Extract values
    jstring jserver = (*env)->GetObjectField(env, config, serverField);
    jint jport = (*env)->GetIntField(env, config, portField);
    jstring jhub = (*env)->GetObjectField(env, config, hubField);
    jstring jusername = (*env)->GetObjectField(env, config, usernameField);
    jstring jpasswordHash = (*env)->GetObjectField(env, config, passwordHashField);
    jboolean juseEncrypt = (*env)->GetBooleanField(env, config, useEncryptField);
    jboolean juseCompress = (*env)->GetBooleanField(env, config, useCompressField);
    
    // Convert to C strings
    const char* server = getStringUTF(env, jserver);
    const char* hub = getStringUTF(env, jhub);
    const char* username = getStringUTF(env, jusername);
    const char* passwordHash = getStringUTF(env, jpasswordHash);
    
    // Create C config
    MobileVpnConfig c_config = {0};
    c_config.server = server;
    c_config.port = (uint16_t)jport;
    c_config.hub = hub;
    c_config.username = username;
    c_config.password_hash = passwordHash;
    c_config.use_encrypt = juseEncrypt == JNI_TRUE;
    c_config.use_compress = juseCompress == JNI_TRUE;
    c_config.half_connection = false;
    c_config.max_connection = 1;
    
    // Android-optimized performance settings
    c_config.recv_queue_size = 128;
    c_config.send_queue_size = 128;
    c_config.packet_pool_size = 256;
    c_config.batch_size = 32;
    
    // Create VPN handle
    MobileVpnHandle handle = mobile_vpn_create(&c_config);
    
    // Release strings
    releaseStringUTF(env, jserver, server);
    releaseStringUTF(env, jhub, hub);
    releaseStringUTF(env, jusername, username);
    releaseStringUTF(env, jpasswordHash, passwordHash);
    
    if (handle == NULL) {
        LOGE("Failed to create VPN handle");
        return 0;
    }
    
    LOGI("VPN handle created: %p", handle);
    return (jlong)(intptr_t)handle;
}

JNIEXPORT void JNICALL
Java_com_softether_vpn_MobileVpn_destroy(JNIEnv* env, jclass clazz, jlong handle) {
    LOGI("Destroying VPN handle: %p", (void*)(intptr_t)handle);
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    mobile_vpn_destroy(vpn_handle);
}

JNIEXPORT jint JNICALL
Java_com_softether_vpn_MobileVpn_connect(JNIEnv* env, jclass clazz, jlong handle) {
    LOGI("Connecting VPN: %p", (void*)(intptr_t)handle);
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    return mobile_vpn_connect(vpn_handle);
}

JNIEXPORT jint JNICALL
Java_com_softether_vpn_MobileVpn_disconnect(JNIEnv* env, jclass clazz, jlong handle) {
    LOGI("Disconnecting VPN: %p", (void*)(intptr_t)handle);
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    return mobile_vpn_disconnect(vpn_handle);
}

// ============================================================================
// JNI Exports - Status & Stats
// ============================================================================

JNIEXPORT jint JNICALL
Java_com_softether_vpn_MobileVpn_getStatus(JNIEnv* env, jclass clazz, jlong handle) {
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    return (jint)mobile_vpn_get_status(vpn_handle);
}

JNIEXPORT jboolean JNICALL
Java_com_softether_vpn_MobileVpn_isConnected(JNIEnv* env, jclass clazz, jlong handle) {
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    return mobile_vpn_is_connected(vpn_handle) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobject JNICALL
Java_com_softether_vpn_MobileVpn_getStats(JNIEnv* env, jclass clazz, jlong handle) {
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    
    MobileVpnStats stats = {0};
    int result = mobile_vpn_get_stats(vpn_handle, &stats);
    
    if (result != 0) {
        return NULL;
    }
    
    // Create VpnStats Java object
    jclass statsClass = (*env)->FindClass(env, "com/softether/vpn/VpnStats");
    jmethodID constructor = (*env)->GetMethodID(env, statsClass, "<init>", "(JJJJJJJ)V");
    
    return (*env)->NewObject(env, statsClass, constructor,
                            (jlong)stats.bytes_sent,
                            (jlong)stats.bytes_received,
                            (jlong)stats.packets_sent,
                            (jlong)stats.packets_received,
                            (jlong)stats.connected_duration_ms,
                            (jlong)stats.queue_drops,
                            (jlong)stats.errors);
}

JNIEXPORT jobject JNICALL
Java_com_softether_vpn_MobileVpn_getNetworkInfo(JNIEnv* env, jclass clazz, jlong handle) {
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    
    MobileNetworkInfo info = {0};
    int result = mobile_vpn_get_network_info(vpn_handle, &info);
    
    if (result != 0) {
        return NULL;
    }
    
    // Convert IP addresses to strings
    char ip_str[16], gateway_str[16], netmask_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", 
             info.ip_address[0], info.ip_address[1], info.ip_address[2], info.ip_address[3]);
    snprintf(gateway_str, sizeof(gateway_str), "%d.%d.%d.%d",
             info.gateway[0], info.gateway[1], info.gateway[2], info.gateway[3]);
    snprintf(netmask_str, sizeof(netmask_str), "%d.%d.%d.%d",
             info.netmask[0], info.netmask[1], info.netmask[2], info.netmask[3]);
    
    // Build DNS server array
    jobjectArray dns_array = (*env)->NewObjectArray(env, 4, (*env)->FindClass(env, "java/lang/String"), NULL);
    for (int i = 0; i < 4; i++) {
        if (info.dns_servers[i][0] != 0) {
            char dns_str[16];
            snprintf(dns_str, sizeof(dns_str), "%d.%d.%d.%d",
                    info.dns_servers[i][0], info.dns_servers[i][1], 
                    info.dns_servers[i][2], info.dns_servers[i][3]);
            (*env)->SetObjectArrayElement(env, dns_array, i, (*env)->NewStringUTF(env, dns_str));
        }
    }
    
    // Create NetworkInfo Java object
    jclass infoClass = (*env)->FindClass(env, "com/softether/vpn/NetworkInfo");
    jmethodID constructor = (*env)->GetMethodID(env, infoClass, "<init>", 
                                                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;I)V");
    
    return (*env)->NewObject(env, infoClass, constructor,
                            (*env)->NewStringUTF(env, ip_str),
                            (*env)->NewStringUTF(env, gateway_str),
                            (*env)->NewStringUTF(env, netmask_str),
                            dns_array,
                            (jint)info.mtu);
}

// ============================================================================
// JNI Exports - Packet I/O
// ============================================================================

JNIEXPORT jint JNICALL
Java_com_softether_vpn_MobileVpn_readPacket(JNIEnv* env, jclass clazz, jlong handle, 
                                             jbyteArray buffer, jint timeout) {
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    
    jsize buffer_len = (*env)->GetArrayLength(env, buffer);
    jbyte* buffer_ptr = (*env)->GetByteArrayElements(env, buffer, NULL);
    
    int result = mobile_vpn_read_packet(vpn_handle, (uint8_t*)buffer_ptr, 
                                       (uint64_t)buffer_len, (uint32_t)timeout);
    
    (*env)->ReleaseByteArrayElements(env, buffer, buffer_ptr, 0);
    
    return (jint)result;
}

JNIEXPORT jint JNICALL
Java_com_softether_vpn_MobileVpn_writePacket(JNIEnv* env, jclass clazz, jlong handle, 
                                              jbyteArray data, jint length) {
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    
    jbyte* data_ptr = (*env)->GetByteArrayElements(env, data, NULL);
    
    int result = mobile_vpn_write_packet(vpn_handle, (const uint8_t*)data_ptr, (uint64_t)length);
    
    (*env)->ReleaseByteArrayElements(env, data, data_ptr, JNI_ABORT);
    
    return (jint)result;
}

// ============================================================================
// JNI Exports - Utility
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_softether_vpn_MobileVpn_getVersion(JNIEnv* env, jclass clazz) {
    const char* version = mobile_vpn_get_version();
    return (*env)->NewStringUTF(env, version);
}

JNIEXPORT jstring JNICALL
Java_com_softether_vpn_MobileVpn_getBuildInfo(JNIEnv* env, jclass clazz) {
    const char* build_info = mobile_vpn_get_build_info();
    return (*env)->NewStringUTF(env, build_info);
}

JNIEXPORT jstring JNICALL
Java_com_softether_vpn_MobileVpn_getError(JNIEnv* env, jclass clazz, jlong handle) {
    MobileVpnHandle vpn_handle = (MobileVpnHandle)(intptr_t)handle;
    const char* error = mobile_vpn_get_error(vpn_handle);
    return (*env)->NewStringUTF(env, error);
}
