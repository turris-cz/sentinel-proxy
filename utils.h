
#define CHECK_ERR(CMD, ...) \
	do { \
		if (CMD) { \
			fprintf(stderr, __VA_ARGS__); \
			return -1; \
		} \
	} while (0)
