TESTS += %reldir%/unittests

check_PROGRAMS += %reldir%/unittests

%canon_reldir%_unittests_SOURCES = \
	${proxy_sources} \
	%reldir%/unittests.c \
	%reldir%/con_peer.c \
	%reldir%/con_peer_list.c \
	%reldir%/proxy_conf.c

%canon_reldir%_unittests_CFLAGS = \
	$(sentinel_proxy_CFLAGS) \
	$(check_CFLAGS)
%canon_reldir%_unittests_LDFLAGS = \
	$(sentinel_proxy_LDFLAGS) \
	$(check_LIBS)
%canon_reldir%_unittests_LDADD = \
	$(sentinel_proxy_LDADD)
