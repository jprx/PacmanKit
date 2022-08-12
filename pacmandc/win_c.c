#include <os/log.h>

#define LOG_PREFIX "[PacmanKit]"

void win_c(void) {
    os_log(OS_LOG_DEFAULT, LOG_PREFIX "You won!\n");
}
