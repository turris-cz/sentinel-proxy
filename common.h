#include "log.h"

#define TOPIC_PREFIX "sentinel/collect/"
#define TOPIC_PREFIX_LEN strlen(TOPIC_PREFIX)
#define ZMQ_MAX_TOPIC_LEN 256

#define TRACE_FUNC TRACE(__func__)

#define CHECK_ERR_LOG(CMD, ...) \
	do { \
		if (CMD) { \
			ERROR(__VA_ARGS__); \
			return -1; \
		} \
	} while (0)

#define CHECK_ERR_VOID_LOG(CMD, ...) \
	do { \
		if (CMD) { \
			ERROR(__VA_ARGS__); \
			return; \
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
