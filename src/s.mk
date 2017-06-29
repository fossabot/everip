#geofront
SRCS	+= geofront/geofront.c
SRCS	+= geofront/conduits.c

#central dogma
SRCS	+= centraldogma/crypto.c
#SRCS	+= centraldogma/relaymap.c
#SRCS	+= centraldogma/manager.c
#SRCS	+= centraldogma/cmdcenter.c

#terminal dogma
SRCS	+= terminaldogma/terminaldogma.c
ifeq ($(OS),darwin)
SRCS	+= terminaldogma/tun_darwin.c
endif
ifeq ($(OS),win32)
SRCS	+= terminaldogma/tun_win32.c
endif
ifeq ($(OS),linux)
SRCS	+= terminaldogma/tun_linux.c
endif

#magi (pathfinder)
#SRCS	+= magi/eventdriver.c
#SRCS	+= magi/starfinder.c

#misato (application)
SRCS	+= misato/everip.c
SRCS	+= misato/cmd.c
SRCS	+= misato/ui.c
SRCS	+= misato/module.c

#ritsuko (utilities)
SRCS	+= ritsuko/log.c
SRCS	+= ritsuko/net.c
SRCS	+= ritsuko/mrpinger.c
SRCS	+= ritsuko/addr.c
SRCS	+= ritsuko/bencode.c
SRCS	+= ritsuko/bencode_dec.c
SRCS	+= ritsuko/bencode_dec_od.c
ifeq ($(OS),darwin)
SRCS	+= ritsuko/net_darwin.c
endif
ifeq ($(OS),win32)
SRCS	+= ritsuko/net_win32.c
endif
ifeq ($(OS),linux)
SRCS	+= ritsuko/net_linux.c
endif

#tree of life
SRCS	+= treeoflife/treeoflife.c

ifneq ($(STATIC),)
SRCS	+= static.c
endif

APP_SRCS += main.c
