
PROJECT	  := everip
VERSION   := 0.1.2
DESCR     := "The EVER/IP(R) Suite"

# Verbose and silent build modes
ifeq ($(V),)
HIDE=@
endif

ifndef LIBRE_MK
LIBRE_PATH := ../libre
LIBRE_MK  := $(shell [ -f $(LIBRE_PATH)/mk/re.mk ] && \
	echo "$(LIBRE_PATH)/mk/re.mk")
endif

USE_OPENSSL :=

include $(LIBRE_MK)
include mk/modules.mk

ifndef LIBSODIUM_PATH
LIBSODIUM_PATH	:= $(shell [ -d ../libs ] && echo "../libs")
endif

CFLAGS    += -I. -Iinclude -I$(LIBRE_INC) -I$(SYSROOT)/include
CFLAGS    += -I$(LIBSODIUM_PATH)/include

CXXFLAGS  += -I. -Iinclude -I$(LIBRE_INC)
CXXFLAGS  += -I$(LIBSODIUM_PATH)/include
CXXFLAGS  += $(EXTRA_CXXFLAGS)

# XXX: common for C/C++
CPPFLAGS += -DHAVE_INTTYPES_H

ifneq ($(LIBSODIUM_PATH),)
SPLINT_OPTIONS += -I$(LIBSODIUM_PATH)/include
CLANG_OPTIONS  += -I$(LIBSODIUM_PATH)/include
endif

# static is good
STATIC    := yes

ifeq ($(OS),freebsd)
ifneq ($(SYSROOT),)
CFLAGS += -I$(SYSROOT)/local/include
endif
endif

ifneq ($(STATIC),)
CFLAGS    += -DSTATIC=1
CXXFLAGS  += -DSTATIC=1
endif
CFLAGS    += -DMODULE_CONF

INSTALL := install
ifeq ($(DESTDIR),)
PREFIX  := /usr/local
else
PREFIX  := /usr
endif
BINDIR	:= $(PREFIX)/bin
INCDIR  := $(PREFIX)/include
BIN	:= $(PROJECT)$(BIN_SUFFIX)
TEST_BIN	:= selftest$(BIN_SUFFIX)
SHARED  := lib$(PROJECT)$(LIB_SUFFIX)
STATICLIB  := libeverip.a
ifeq ($(STATIC),)
MOD_BINS:= $(patsubst %,%$(MOD_SUFFIX),$(MODULES))
endif
APP_MK	:= src/s.mk
TEST_MK	:= test/s.mk
MOD_MK	:= $(patsubst %,modules/%/module.mk,$(MODULES))
MOD_BLD	:= $(patsubst %,$(BUILD)/modules/%,$(MODULES))
LIBDIR     := $(PREFIX)/lib
MOD_PATH   := $(LIBDIR)/$(PROJECT)/modules
SHARE_PATH := $(PREFIX)/share/$(PROJECT)
CFLAGS     += -DPREFIX=\"$(PREFIX)\"


all: sanity $(MOD_BINS) $(BIN)

.PHONY: modules
modules:	$(MOD_BINS)

include $(APP_MK)
include $(TEST_MK)
include $(MOD_MK)

OBJS      := $(patsubst %.c,$(BUILD)/src/%.o,$(filter %.c,$(SRCS)))
OBJS      += $(patsubst %.m,$(BUILD)/src/%.o,$(filter %.m,$(SRCS)))
OBJS      += $(patsubst %.S,$(BUILD)/src/%.o,$(filter %.S,$(SRCS)))

APP_OBJS  := $(OBJS) $(patsubst %.c,$(BUILD)/src/%.o,$(APP_SRCS)) $(MOD_OBJS)

LIB_OBJS  := $(OBJS) $(MOD_OBJS)

TEST_OBJS := $(patsubst %.c,$(BUILD)/test/%.o,$(filter %.c,$(TEST_SRCS)))
TEST_OBJS += $(patsubst %.cpp,$(BUILD)/test/%.o,$(filter %.cpp,$(TEST_SRCS)))


# Static build: include module linker-flags in binary
ifneq ($(STATIC),)
LIBS      += $(MOD_LFLAGS)
else
LIBS      += -L$(SYSROOT)/local/lib
MOD_LFLAGS += -L$(SYSROOT)/local/lib
endif

LIBS      += -lm
LIBS      += -L$(SYSROOT)/lib

ifeq ($(OS),win32)
TEST_LIBS += -static-libgcc
endif


-include $(APP_OBJS:.o=.d)

-include $(TEST_OBJS:.o=.d)

sanity:
ifeq ($(SIGNED_CLA_LICENSE),)
	@echo "STOP: TRADEMARK CONFLICT: EVER/IP(R) cannot be compiled without obtaining an express trademark license from connectFree Licensing"
	@exit 2
endif
ifeq ($(LIBRE_MK),)
	@echo "ERROR: Missing common makefile for libre. Check LIBRE_MK"
	@exit 2
endif
ifeq ($(LIBRE_INC),)
	@echo "ERROR: Missing header files for libre. Check LIBRE_INC"
	@exit 2
endif
ifeq ($(LIBRE_SO),)
	@echo "ERROR: Missing library files for libre. Check LIBRE_SO"
	@exit 2
endif
ifeq ($(LIBSODIUM_PATH),)
	@echo "ERROR: Missing header files for libsodium. Check LIBSODIUM_PATH"
	@exit 2
endif

ifneq ($(USEGENDO),)
LIBS  += ../libgendo/libgendo.a
LIB_OBJS+= ../libgendo/libgendo.a
CFLAGS    += -I../libgendo/include
CFLAGS += -DHAVE_GENDO
endif

LIBS  += $(LIBSODIUM_PATH)/lib/libsodium.a
LIB_OBJS+= $(LIBSODIUM_PATH)/lib/libsodium.a

Makefile:	mk/*.mk $(MOD_MK) $(LIBRE_MK)

$(SHARED): $(LIB_OBJS)
	@echo "  LD      $@"
	$(HIDE)$(LD) $(LFLAGS) $(SH_LFLAGS) $^ -L$(LIBRE_SO) -lre $(LIBS) -o $@

$(STATICLIB): $(LIB_OBJS)
	@echo "  AR      $@"
	@rm -f $@; $(AR) $(AFLAGS) $@ $^
ifneq ($(RANLIB),)
	@echo "  RANLIB  $@"
	$(HIDE)$(RANLIB) $@
endif

# GPROF requires static linking
$(BIN):	$(APP_OBJS)
#ifneq ($(GPROF),)
	@echo "  LDS     $@"
	$(HIDE)$(LD) $(LFLAGS) $(APP_LFLAGS) $^ $(LIBS) $(LIBRE_SO)/libre.a -o $@
#else
#	@echo "  LD      $@"
#	$(HIDE)$(LD) $(LFLAGS) $(APP_LFLAGS) $^ \
#		-L$(LIBRE_SO) -lre $(LIBS) -o $@
#endif

.PHONY: debug
debug:	$(BIN)
	lldb ./$(BIN)

.PHONY: test
test:	$(TEST_BIN)
	./$(TEST_BIN)

.PHONY: dtest
dtest:	$(TEST_BIN)
	lldb ./$(TEST_BIN)

$(TEST_BIN):	$(STATICLIB) $(TEST_OBJS)
	@echo "  LD      $@"
	$(HIDE)$(CXX) $(LFLAGS) $(TEST_OBJS) \
		-L. \
		-l$(PROJECT) $(LIBRE_PATH)/libre.a $(LIBSODIUM_PATH)/lib/libsodium.a $(LIBS) $(TEST_LIBS) -o $@

$(BUILD)/%.o: %.c $(BUILD) Makefile $(APP_MK)
	@echo "  CC      $@"
	$(HIDE)mkdir -p $(shell dirname "$@")
	$(HIDE)$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)

$(BUILD)/%.o: %.cpp $(BUILD) Makefile $(APP_MK)
	@echo "  CXX     $@"
	$(HIDE)$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@ $(DFLAGS)

$(BUILD)/%.o: %.m $(BUILD) Makefile $(APP_MK)
	@echo "  OC      $@"
	$(HIDE)$(CC) $(CFLAGS) $(OBJCFLAGS) -c $< -o $@ $(DFLAGS)

$(BUILD)/%.o: %.S $(BUILD) Makefile $(APP_MK)
	@echo "  AS      $@"
	$(HIDE)$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)

$(BUILD): Makefile
	@mkdir -p $(BUILD)/src $(MOD_BLD) $(BUILD)/test/mock $(BUILD)/test/sip
	@touch $@

.PHONY: clean
clean:
	@rm -rf $(BIN) $(MOD_BINS) $(SHARED) $(BUILD) $(TEST_BIN) \
		$(STATICLIB) libeverip.pc
	@rm -f *stamp \
	`find . -name "*.[od]"` \
	`find . -name "*~"` \
	`find . -name "\.\#*"`

#I HATE PERL
version:
	@perl -pi -e 's/EVERIP_VERSION.*/EVERIP_VERSION \"$(VERSION)"/' \
		include/everip.h
	@perl -pi -e "s/PROJECT_NUMBER         = .*/\
PROJECT_NUMBER         = $(VERSION)/" \
		mk/Doxyfile
	@echo "updating version number to $(VERSION)"

src/static.c: $(BUILD) Makefile $(APP_MK) $(MOD_MK)
	@echo "  SH      $@"
	@echo "/* DO NOT TOUCH */"  > $@
	@echo "#include <re_types.h>"  >> $@
	@echo "#include <re_mod.h>"  >> $@
	@echo ""  >> $@
	@for n in $(MODULES); do \
		echo "extern const struct mod_export exports_$${n};" >> $@ ; \
	done
	@echo ""  >> $@
	@echo "const struct mod_export *mod_table[] = {"  >> $@
	@for n in $(MODULES); do \
		echo "  &exports_$${n},"  >> $@  ; \
	done
	@echo "  NULL"  >> $@
	@echo "};"  >> $@
