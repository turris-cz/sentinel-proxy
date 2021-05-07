#!/bin/sh
valgrind \
	--leak-check=full \
	--show-leak-kinds=definite,indirect,possible \
	--track-fds=yes \
	--track-origins=yes \
	--error-exitcode=1 \
	--show-leak-kinds=definite,indirect,possible --track-fds=yes \
	--error-exitcode=1 --track-origins=yes \
../../sentinel-proxy \
	--log-level=-5 \
	--config ./proxy.cfg \
	--disable-serv-check
