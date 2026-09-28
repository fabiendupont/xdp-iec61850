/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Interop Test Helpers
 *
 * Subprocess management, veth setup, and output parsing for
 * interop tests against libiec61850. No GPL code linked.
 *
 * libiec61850 example programs are used as-is (black-box binaries).
 * Set LIBIEC61850_BUILD_DIR to the libiec61850 build directory
 * (e.g. ~/Code/github.com/mz-automation/libiec61850/build).
 */

#ifndef INTEROP_HELPERS_H
#define INTEROP_HELPERS_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>

/* Test framework macros */
static int interop_tests_run = 0;
static int interop_tests_passed = 0;
static int interop_tests_failed = 0;
static int interop_tests_skipped = 0;

#define INTEROP_TEST(name) do { \
    interop_tests_run++; \
    printf("  [INTEROP] %s ... ", name); \
    fflush(stdout); \
} while (0)

#define INTEROP_PASS() do { \
    interop_tests_passed++; \
    printf("PASS\n"); \
} while (0)

#define INTEROP_FAIL(msg) do { \
    interop_tests_failed++; \
    printf("FAIL: %s\n", msg); \
    return; \
} while (0)

#define INTEROP_SKIP(msg) do { \
    interop_tests_skipped++; \
    printf("SKIP: %s\n", msg); \
    return; \
} while (0)

#define INTEROP_ASSERT(cond) do { \
    if (!(cond)) { INTEROP_FAIL(#cond); } \
} while (0)

#define INTEROP_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
        interop_tests_failed++; \
        return; \
    } \
} while (0)

#define INTEROP_SUMMARY() do { \
    printf("\n=== Interop Summary ===\n"); \
    printf("  Run:     %d\n", interop_tests_run); \
    printf("  Passed:  %d\n", interop_tests_passed); \
    printf("  Failed:  %d\n", interop_tests_failed); \
    printf("  Skipped: %d\n", interop_tests_skipped); \
} while (0)

/*
 * Path to libiec61850 build directory.
 * Set via LIBIEC61850_BUILD_DIR env var.
 * Contains examples/ and src/ (for LD_LIBRARY_PATH).
 */
static char g_libiec_build[512];
static char g_libiec_ldpath[600];

/*
 * Resolve path to a libiec61850 example binary.
 * E.g. interop_example_path(buf, sizeof(buf), "server_example_basic_io", "server_example_basic_io")
 */
static inline bool interop_example_path(char *buf, size_t size,
                                        const char *example_dir,
                                        const char *binary_name)
{
    snprintf(buf, size, "%s/examples/%s/%s",
             g_libiec_build, example_dir, binary_name);
    return access(buf, X_OK) == 0;
}

/*
 * Find libiec61850 build directory.
 * Checks LIBIEC61850_BUILD_DIR env var, then common locations.
 */
static inline bool interop_find_libiec61850(void)
{
    const char *env = getenv("LIBIEC61850_BUILD_DIR");
    if (env) {
        snprintf(g_libiec_build, sizeof(g_libiec_build), "%s", env);
    } else {
        /* Try common locations */
        const char *home = getenv("HOME");
        if (!home) return false;

        const char *paths[] = {
            "%s/Code/github.com/mz-automation/libiec61850/build",
            "%s/libiec61850/build",
            NULL
        };

        bool found = false;
        for (int i = 0; paths[i]; i++) {
            snprintf(g_libiec_build, sizeof(g_libiec_build), paths[i], home);
            char test[600];
            snprintf(test, sizeof(test), "%s/examples", g_libiec_build);
            if (access(test, F_OK) == 0) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }

    /* Set LD_LIBRARY_PATH for shared lib */
    snprintf(g_libiec_ldpath, sizeof(g_libiec_ldpath),
             "%s/src", g_libiec_build);

    /* Verify at least one example exists */
    char test[600];
    return interop_example_path(test, sizeof(test),
                                "server_example_basic_io",
                                "server_example_basic_io");
}

/*
 * Check if libiec61850 example programs are available.
 */
static inline bool interop_check_prerequisites(void)
{
    if (!interop_find_libiec61850()) {
        printf("SKIP: libiec61850 build not found "
               "(set LIBIEC61850_BUILD_DIR)\n");
        return false;
    }
    return true;
}

static inline bool interop_is_root(void)
{
    return geteuid() == 0;
}

static inline int interop_create_veth(const char *name0, const char *name1)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "ip link add %s type veth peer name %s && "
        "ip link set %s up && ip link set %s up",
        name0, name1, name0, name1);
    return system(cmd);
}

static inline void interop_destroy_veth(const char *name0)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", name0);
    (void)system(cmd);
}

/*
 * Run a program and capture its stdout.
 * Sets LD_LIBRARY_PATH for libiec61850 shared lib.
 */
static inline int interop_run_program(const char *binary, char *const argv[],
                                      char *output, size_t output_size,
                                      int timeout_ms)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        setenv("LD_LIBRARY_PATH", g_libiec_ldpath, 1);
        execv(binary, argv);
        _exit(127);
    }

    close(pipefd[1]);

    if (timeout_ms > 0) {
        int flags = fcntl(pipefd[0], F_GETFL, 0);
        fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }

    size_t total = 0;
    int elapsed = 0;
    bool timed_out = false;

    while (total < output_size - 1) {
        ssize_t n = read(pipefd[0], output + total, output_size - 1 - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n == 0) {
            break;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (timeout_ms > 0 && elapsed >= timeout_ms) {
                timed_out = true;
                kill(pid, SIGTERM);
                break;
            }
            usleep(10000);
            elapsed += 10;
        } else {
            break;
        }
    }
    output[total] = '\0';
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    if (timed_out) return -ETIMEDOUT;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/*
 * Start a program in the background.
 * Sets LD_LIBRARY_PATH for libiec61850 shared lib.
 */
static inline pid_t interop_start_bg(const char *binary,
                                     char *const argv[],
                                     int *out_fd)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        if (out_fd) {
            dup2(pipefd[1], STDOUT_FILENO);
            dup2(pipefd[1], STDERR_FILENO);
        } else {
            /* No output capture — redirect to /dev/null to avoid SIGPIPE */
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        close(pipefd[1]);
        setenv("LD_LIBRARY_PATH", g_libiec_ldpath, 1);
        execv(binary, argv);
        _exit(127);
    }

    close(pipefd[1]);
    if (out_fd)
        *out_fd = pipefd[0];
    else
        close(pipefd[0]);

    return pid;
}

/*
 * Wait for a port to become available (TCP listen).
 */
static inline bool interop_wait_for_port(uint16_t port, int timeout_ms)
{
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "ss -tlnH sport = :%u 2>/dev/null", port);
        FILE *f = popen(cmd, "r");
        if (f) {
            char buf[256];
            bool found = fgets(buf, sizeof(buf), f) != NULL && strlen(buf) > 0;
            pclose(f);
            if (found) return true;
        }
        usleep(50000);
        elapsed += 50;
    }
    return false;
}

static inline void interop_stop_helper(pid_t pid)
{
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    usleep(100000);
    int status;
    if (waitpid(pid, &status, WNOHANG) == 0) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
}

#endif /* INTEROP_HELPERS_H */
