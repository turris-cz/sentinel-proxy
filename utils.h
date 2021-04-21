#include "log.h"

#define CHECK_ERR_LOG(CMD, ...) \
	do { \
		if (CMD) { \
			ERROR(__VA_ARGS__); \
			return -1; \
		} \
	} while (0)

#define CHECK_ERR(CMD) \
	do { \
		if (CMD) { \
			return -1; \
		} \
	} while (0)

#define LOG_ERR(CMD, ...) \
	do { \
		if (CMD) { \
			ERROR(__VA_ARGS__); \
		} \
	} while (0)
