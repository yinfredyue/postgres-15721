# src/bin/tscout_test_timing/Makefile

PGFILEDESC = "tscout_test_timing - test timing overhead"
PGAPPICON = win32

subdir = src/bin/tscout_test_timing
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS = \
	$(WIN32RES) \
	tscout_test_timing.o

all: tscout_test_timing

tscout_test_timing: $(OBJS) | submake-libpgport
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@$(X)

install: all installdirs
	$(INSTALL_PROGRAM) tscout_test_timing$(X) '$(DESTDIR)$(bindir)/tscout_test_timing$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

check:
	$(prove_check)

installcheck:
	$(prove_installcheck)

uninstall:
	rm -f '$(DESTDIR)$(bindir)/tscout_test_timing$(X)'

clean distclean maintainer-clean:
	rm -f tscout_test_timing$(X) $(OBJS)
	rm -rf tmp_check
