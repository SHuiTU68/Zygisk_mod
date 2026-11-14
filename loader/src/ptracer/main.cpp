#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/system_properties.h>

#include "main.hpp"
#include "utils.hpp"
#include "daemon.h"
#include <sys/mount.h>

using namespace std::string_view_literals;

namespace {

constexpr const char *kDenylistModePath =
        "/data/adb/modules/admirepowered/denylist_mode";

int denylist_mode(int argc, char **argv) {
    if (argc == 4) {
        const char *mode = argv[3];
        if (strcmp(mode, "just_umount") != 0 && strcmp(mode, "enforce") != 0) {
            fprintf(stderr, "Invalid denylist mode: %s\n", mode);
            return 1;
        }
        FILE *file = fopen(kDenylistModePath, "w");
        if (file == nullptr) {
            perror("fopen denylist_mode");
            return 1;
        }
        fprintf(file, "%s\n", mode);
        fclose(file);
        printf("denylist mode: %s\n", mode);
        return 0;
    }
    if (argc == 3) {
        char mode[32] = {};
        FILE *file = fopen(kDenylistModePath, "r");
        if (file != nullptr && fgets(mode, sizeof(mode), file) != nullptr) {
            mode[strcspn(mode, "\r\n")] = '\0';
        }
        if (file != nullptr) fclose(file);
        printf("denylist mode: %s\n", mode[0] != '\0' ? mode : "just_umount");
        return 0;
    }
    fprintf(stderr, "Usage: %s ctl denylist <just_umount|enforce>\n", argv[0]);
    return 1;
}

}

int main(int argc, char **argv) {
    zygiskd::Init(getenv("TMP_PATH"));
    if (argc >= 2 && argv[1] == "monitor"sv) {
        init_monitor();
        return 0;
    } else if (argc >= 3 && argv[1] == "trace"sv) {
        if (argc >= 4 && argv[3] == "--restart"sv) {
            zygiskd::ZygoteRestart();
        }
        auto pid = strtol(argv[2], 0, 0);
        if (!trace_zygote(pid)) {
            kill(pid, SIGKILL);
            return 1;
        }
        return 0;
    } else if (argc >= 3 && argv[1] == "ctl"sv && argv[2] == "denylist"sv) {
        return denylist_mode(argc, argv);
    } else if (argc >= 2 && argv[1] == "ctl"sv) {
        if (argc == 3) {
            if (argv[2] == "start"sv) {
                send_control_command(START);
                return 0;
            } else if (argv[2] == "stop"sv) {
                send_control_command(STOP);
                return 0;
            } else if (argv[2] == "exit"sv) {
                send_control_command(EXIT);
                return 0;
            }
        }
        printf("Zygisk_mod Tracer %s\n", ZKSU_VERSION);
        printf("Usage: %s ctl start|stop|exit|denylist <just_umount|enforce>\n", argv[0]);
        return 1;
    } else if (argc >= 2 && argv[1] == "version"sv) {
        printf("Zygisk_mod Tracer %s\n", ZKSU_VERSION);
        return 0;
    } else {
        printf("Zygisk_mod Tracer %s\n", ZKSU_VERSION);
        printf("usage: %s monitor | trace <pid> | ctl <start|stop|exit> | version\n", argv[0]);
        return 1;
    }
}
