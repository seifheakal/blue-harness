/* Carapace anti-Frida detector — implementation (Linux, libc only). */
#define _GNU_SOURCE
#include "carapace_antifrida.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Case-sensitive substring presence of any needle in a line. */
static int has_any(const char *line, const char *const *needles) {
    for (int i = 0; needles[i]; i++)
        if (strstr(line, needles[i]))
            return 1;
    return 0;
}

/* MAPS: a frida-agent / frida-gadget / gum library mapped into us. */
static int scan_maps(void) {
    static const char *const needles[] = {
        "frida-agent", "frida-gadget", "frida_agent", "libgum", "gum-js", "frida", NULL
    };
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[4096];
    int hit = 0;
    while (fgets(line, sizeof line, f))
        if (has_any(line, needles)) { hit = 1; break; }
    fclose(f);
    return hit;
}

/* THREADS: a Frida worker thread name in /proc/self/task/<tid>/comm.
 * We use Frida-specific names; generic GLib names (gmain/gdbus) are deliberately
 * NOT matched to avoid false positives on ordinary GTK/GLib apps (honesty). */
static int scan_threads(void) {
    static const char *const needles[] = { "gum-js-loop", "gmain-frida", "frida", "pool-frida", NULL };
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    struct dirent *e;
    int hit = 0;
    while ((e = readdir(d)) && !hit) {
        if (e->d_name[0] == '.') continue;
        char path[300], comm[128];
        snprintf(path, sizeof path, "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (fgets(comm, sizeof comm, f))
            if (has_any(comm, needles)) hit = 1;
        fclose(f);
    }
    closedir(d);
    return hit;
}

/* PORT: is something LISTENing on the default frida-server port 27042?
 * A loopback connect() completes the handshake iff a listener is present (it
 * lands in the accept queue even before accept() is called), so this is portable
 * where a namespaced/stale /proc/net/tcp would not show the socket. */
static int scan_port(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(27042);
    int r = connect(s, (struct sockaddr *)&a, sizeof a);
    close(s);
    return r == 0;          /* connected => a listener is there */
}

int carapace_antifrida_scan(char *detail, size_t detail_len) {
    int flags = 0;
    if (scan_maps())    flags |= CARAPACE_FRIDA_MAPS;
    if (scan_threads()) flags |= CARAPACE_FRIDA_THREADS;
    if (scan_port())    flags |= CARAPACE_FRIDA_PORT;

    if (detail && detail_len) {
        snprintf(detail, detail_len, "%s%s%s%s",
                 flags ? "frida:" : "clean",
                 (flags & CARAPACE_FRIDA_MAPS)    ? " maps" : "",
                 (flags & CARAPACE_FRIDA_THREADS) ? " threads" : "",
                 (flags & CARAPACE_FRIDA_PORT)    ? " port27042" : "");
    }
    return flags;
}
