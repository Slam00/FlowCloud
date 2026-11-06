#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <dlfcn.h>

#include <jni.h>
#include <android/log.h>

#include "byedpi/error.h"
#include "byedpi/params.h"
#include "main.h"

typedef int (*flow_router_start_fn)(char *, char *, char *, char *, char *, char *);
typedef void (*flow_router_stop_fn)(void);
typedef char *(*flow_router_error_fn)(void);
typedef char *(*flow_router_diagnostics_fn)(void);
typedef char *(*flow_router_generate_keypair_fn)(void);
typedef void (*flow_router_free_fn)(char *);
typedef void (*flow_router_set_network_fn)(long long);

static void *flow_router_library = NULL;

static void *flow_router_symbol(const char *name) {
    if (!flow_router_library) {
        flow_router_library = dlopen("libflowrouter.so", RTLD_NOW | RTLD_LOCAL);
    }
    if (!flow_router_library) {
        return NULL;
    }
    return dlsym(flow_router_library, name);
}

JNIEXPORT jint JNICALL
Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniStart(
        JNIEnv *env,
        __attribute__((unused)) jobject thiz,
        jstring listen_address,
        jstring byedpi_address,
        jstring dns_relay_address,
        jstring warp_rules,
        jstring byedpi_rules,
        jstring warp_config) {
    flow_router_start_fn start = (flow_router_start_fn) flow_router_symbol("FlowRouterStart");
    if (!start) {
        return -100;
    }
    const char *listen_value = (*env)->GetStringUTFChars(env, listen_address, 0);
    const char *byedpi_value = (*env)->GetStringUTFChars(env, byedpi_address, 0);
    const char *dns_relay_value = (*env)->GetStringUTFChars(env, dns_relay_address, 0);
    const char *warp_rules_value = (*env)->GetStringUTFChars(env, warp_rules, 0);
    const char *byedpi_rules_value = (*env)->GetStringUTFChars(env, byedpi_rules, 0);
    const char *config_value = (*env)->GetStringUTFChars(env, warp_config, 0);
    int result = start(
            (char *) listen_value,
            (char *) byedpi_value,
            (char *) dns_relay_value,
            (char *) warp_rules_value,
            (char *) byedpi_rules_value,
            (char *) config_value
    );
    (*env)->ReleaseStringUTFChars(env, listen_address, listen_value);
    (*env)->ReleaseStringUTFChars(env, byedpi_address, byedpi_value);
    (*env)->ReleaseStringUTFChars(env, dns_relay_address, dns_relay_value);
    (*env)->ReleaseStringUTFChars(env, warp_rules, warp_rules_value);
    (*env)->ReleaseStringUTFChars(env, byedpi_rules, byedpi_rules_value);
    (*env)->ReleaseStringUTFChars(env, warp_config, config_value);
    return result;
}

JNIEXPORT void JNICALL
Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniStop(
        __attribute__((unused)) JNIEnv *env,
        __attribute__((unused)) jobject thiz) {
    flow_router_stop_fn stop = (flow_router_stop_fn) flow_router_symbol("FlowRouterStop");
    if (stop) {
        stop();
    }
}

JNIEXPORT jstring JNICALL
Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniLastError(
        JNIEnv *env,
        __attribute__((unused)) jobject thiz) {
    flow_router_error_fn last_error =
            (flow_router_error_fn) flow_router_symbol("FlowRouterLastError");
    flow_router_free_fn free_error =
            (flow_router_free_fn) flow_router_symbol("FlowRouterFree");
    if (!last_error || !free_error) {
        const char *error = dlerror();
        return (*env)->NewStringUTF(env, error ? error : "libflowrouter.so is unavailable");
    }
    char *value = last_error();
    jstring result = (*env)->NewStringUTF(env, value ? value : "");
    if (value) {
        free_error(value);
    }
    return result;
}

JNIEXPORT jstring JNICALL
Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniDrainDiagnostics(
        JNIEnv *env,
        __attribute__((unused)) jobject thiz) {
    flow_router_diagnostics_fn drain_diagnostics =
            (flow_router_diagnostics_fn) flow_router_symbol("FlowRouterDrainDiagnostics");
    flow_router_free_fn free_value =
            (flow_router_free_fn) flow_router_symbol("FlowRouterFree");
    if (!drain_diagnostics || !free_value) {
        return (*env)->NewStringUTF(env, "");
    }
    char *value = drain_diagnostics();
    jstring result = (*env)->NewStringUTF(env, value ? value : "");
    if (value) {
        free_value(value);
    }
    return result;
}

JNIEXPORT void JNICALL
Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniSetPhysicalNetwork(
        __attribute__((unused)) JNIEnv *env,
        __attribute__((unused)) jobject thiz,
        jlong network_handle) {
    flow_router_set_network_fn set_network =
            (flow_router_set_network_fn) flow_router_symbol("FlowRouterSetPhysicalNetwork");
    if (set_network) {
        set_network((long long) network_handle);
    }
}

JNIEXPORT jstring JNICALL
Java_io_github_dovecoteescapee_byedpi_core_AutoRouteProxy_jniGenerateKeyPair(
        JNIEnv *env,
        __attribute__((unused)) jobject thiz) {
    flow_router_generate_keypair_fn generate_keypair =
            (flow_router_generate_keypair_fn) flow_router_symbol("FlowRouterGenerateKeyPair");
    flow_router_free_fn free_value =
            (flow_router_free_fn) flow_router_symbol("FlowRouterFree");
    if (!generate_keypair || !free_value) {
        return (*env)->NewStringUTF(env, "");
    }
    char *value = generate_keypair();
    jstring result = (*env)->NewStringUTF(env, value ? value : "");
    if (value) {
        free_value(value);
    }
    return result;
}

extern int server_fd;

static struct params default_params;
static pthread_mutex_t proxy_mutex = PTHREAD_MUTEX_INITIALIZER;
static int proxy_running = 0;

int __wrap_daemon(__attribute__((unused)) int nochdir,
                  __attribute__((unused)) int noclose) {
    LOG(LOG_S, "daemon mode is not supported inside the app");
    errno = EPERM;
    return -1;
}

JNIEXPORT jint JNI_OnLoad(
        __attribute__((unused)) JavaVM *vm,
        __attribute__((unused)) void *reserved) {
    default_params = params;
    server_fd = -1;
    return JNI_VERSION_1_6;
}

JNIEXPORT jint JNICALL
Java_io_github_dovecoteescapee_byedpi_core_ByeDpiProxy_jniStartProxy(
        JNIEnv *env,
        __attribute__((unused)) jobject thiz,
        jobjectArray args) {
    pthread_mutex_lock(&proxy_mutex);
    if (proxy_running) {
        pthread_mutex_unlock(&proxy_mutex);
        LOG(LOG_S, "proxy is already running");
        return -1;
    }
    proxy_running = 1;
    pthread_mutex_unlock(&proxy_mutex);

    int argc = (*env)->GetArrayLength(env, args);
    char **argv = calloc(argc + 1, sizeof(char *));
    int result = -1;
    if (!argv) {
        goto done;
    }
    for (int i = 0; i < argc; i++) {
        jstring arg = (jstring) (*env)->GetObjectArrayElement(env, args, i);
        if (!arg) {
            goto cleanup;
        }
        const char *arg_str = (*env)->GetStringUTFChars(env, arg, NULL);
        if (arg_str) {
            argv[i] = strdup(arg_str);
            (*env)->ReleaseStringUTFChars(env, arg, arg_str);
        }
        (*env)->DeleteLocalRef(env, arg);
        if (!argv[i]) {
            goto cleanup;
        }
    }

    pthread_mutex_lock(&proxy_mutex);
    // The core keeps its state in globals: start every run from a clean copy.
    params = default_params;
    server_fd = -1;
    optind = 1;
    optreset = 1;
    pthread_mutex_unlock(&proxy_mutex);

    LOG(LOG_S, "starting proxy with %d args", argc);
    result = main(argc, argv);
    LOG(LOG_S, "proxy return code %d", result);

cleanup:
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
done:
    pthread_mutex_lock(&proxy_mutex);
    server_fd = -1;
    proxy_running = 0;
    pthread_mutex_unlock(&proxy_mutex);
    return result;
}

JNIEXPORT jint JNICALL
Java_io_github_dovecoteescapee_byedpi_core_ByeDpiProxy_jniStopProxy(
        __attribute__((unused)) JNIEnv *env,
        __attribute__((unused)) jobject thiz) {
    pthread_mutex_lock(&proxy_mutex);
    int result = -1;
    if (proxy_running && server_fd >= 0) {
        LOG(LOG_S, "stop_proxy, fd: %d", server_fd);
        result = shutdown(server_fd, SHUT_RDWR);
        if (result < 0) {
            uniperror("shutdown");
        }
    }
    pthread_mutex_unlock(&proxy_mutex);
    return result;
}

JNIEXPORT jboolean JNICALL
Java_io_github_dovecoteescapee_byedpi_core_ByeDpiProxy_jniIsListening(
        __attribute__((unused)) JNIEnv *env,
        __attribute__((unused)) jobject thiz) {
    pthread_mutex_lock(&proxy_mutex);
    jboolean listening = proxy_running && server_fd >= 0;
    pthread_mutex_unlock(&proxy_mutex);
    return listening;
}
