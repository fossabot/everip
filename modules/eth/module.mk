MOD		:= eth

ifeq ($(OS),darwin)
$(MOD)_SRCS	+= eth_darwin.c
else
ifeq ($(OS),linux)
$(MOD)_SRCS	+= eth_linux.c
else
$(MOD)_SRCS	+= eth_dummy.c
endif
endif

include mk/mod.mk
