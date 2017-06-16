MODULES   += dcmd
MODULES   += udp
MODULES   += eth

#ui
ifeq ($(OS),win32)
MODULES   += wincon
else
MODULES   += stdio
endif