
DFLAGS = -g -release -betterC -Oz -vgc
CFLAGS = -g -Os -Wall -Wpedantic

OBJS = openssl_glues.o ../acme/openssl_glues.di

# DISASM = $(OBJS:%.o=%.asm)

#%.asm : %.o
#	$(CROSSCOMPILE)objdump -dSth $< | ddemangle > ${DUB_PACKAGE_DIR}$@

%.o : %.d
	$(CROSSCOMPILE)$(DC) -c $(DFLAGS) $< -of ${DUB_PACKAGE_DIR}$@

%.o : %.c %.h
	$(CROSSCOMPILE)$(CC) -c $(CFLAGS) $< -o ${DUB_PACKAGE_DIR}$@

../acme/openssl_glues.di : openssl_glues.h Makefile
	@echo "Create DI file : openssl_glues.di"
	@echo "/* DI file to call openssl_glues.c code */" > $@
	@echo "module acme.openssl_glues;" >> $@
	@echo "import core.stdc.time;" >> $@
	@echo "extern(C) :" >> $@
	@cat $< | sed -e 's/(void)/()/g' >> $@

all : $(OBJS) $(DISASM)

clean:
	rm -f *.o *.asm

