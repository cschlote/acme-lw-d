
DFLAGS = -g -release -betterC -Oz -vgc
CFLAGS = -g -Os -Wall

OBJS = openssl_glues.o openssl_glues.di

DISASM = $(OBJS:%.o=%.asm)

%.asm : %.o
	$(CROSSCOMPILE)objdump -dSth $< | ddemangle > $@

%.o : %.d
	$(CROSSCOMPILE)$(DC) -c $(DFLAGS) $< -of $@

%.o : %.c %.h
	pwd
	$(CROSSCOMPILE)$(CC) -c $(CFLAGS) $< -o $@
	ls

openssl_glues.di : openssl_glues.h Makefile
	@echo "Create DI file : openssl_glues.di"
	@echo "module acme.openssl_glues;" > openssl_glues.di
	@echo "import deimos.openssl.conf;" >> openssl_glues.di
	@echo "import deimos.openssl.evp;" >> openssl_glues.di
	@echo "import deimos.openssl.err;" >> openssl_glues.di
	@echo "import deimos.openssl.pem;" >> openssl_glues.di
	@echo "import deimos.openssl.x509;" >> openssl_glues.di
	@echo "import deimos.openssl.x509v3;" >> openssl_glues.di
	@echo "extern(C) :" >> openssl_glues.di
	@cat $< | sed -e 's/(void)/()/g' >> openssl_glues.di

all : $(OBJS) $(DISASM)

clean:
	rm -f *.o *.asm

