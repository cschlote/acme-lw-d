
DFLAGS = -g -release -betterC -Oz -vgc
CFLAGS = -g -Os -Wall

OBJS = openssl_glues.o openssl_glues.di

# DISASM = $(OBJS:%.o=%.asm)

#%.asm : %.o
#	$(CROSSCOMPILE)objdump -dSth $< | ddemangle > ${DUB_PACKAGE_DIR}$@

%.o : %.d
	$(CROSSCOMPILE)$(DC) -c $(DFLAGS) $< -of ${DUB_PACKAGE_DIR}$@

%.o : %.c %.h
	pwd
	$(CROSSCOMPILE)$(CC) -c $(CFLAGS) $< -o ${DUB_PACKAGE_DIR}$@
	ls

openssl_glues.di : openssl_glues.h Makefile
	@echo "Create DI file : openssl_glues.di"
	@echo "module acme.openssl_glues;" > openssl_glues.di
	@echo "extern(C) :" >> openssl_glues.di
	@cat $< | sed -e 's/(void)/()/g' >> openssl_glues.di

all : $(OBJS) $(DISASM)

clean:
	rm -f *.o *.asm

