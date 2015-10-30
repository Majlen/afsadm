CC = gcc
#CFLAGS = -g

CFLAGS	= `dpkg-buildflags --get CFLAGS`
CFLAGS += `dpkg-buildflags --get CPPFLAGS`
#clang won't shut up about associations in conditional clauses
CFLAGS += -Wno-parentheses

LDFLAGS = `dpkg-buildflags --get LDFLAGS`

#LDFLAGS	= -Wl,-rpath,/usr/lib 

LIBS 	= -L/usr/lib -L. -lkrb5 -lcom_err -lkafs

#CLNTLIBS = -L/usr/lib -lkrb5 -lcom_err -lcrypto -lreadline -lcurses -lk5crypto -lnsl
CLNTLIBS = -L/usr/lib -lkrb5 -lcom_err -l:libreadline.so.6 -lk5crypto
INCLUDES = -I/usr/include

SOURCES=parceconf.c server.c struct.c afsadmd.c afsadmclnt.c
OBJECTS=parseconf.o server.o struct.o afsadmd.o
CLNTOBJECTS=afsadmclnt.o
HEADERS=afsadm.h

#DEFINES        = -D_DEBUG_ -DAFSADMDIR=/usr/afs/afsadm

all:	libkafs.so afsadmd afsadm

build:	all

afsadm: $(CLNTOBJECTS)
	$(CC) $(LDFLAGS) -o $(@) $(CLNTOBJECTS) $(CLNTLIBS)

afsadmd: $(OBJECTS)
	$(CC) $(LDFLAGS) -o $(@) $(OBJECTS) $(LIBS)

libkafs.so:
	#gcc -DAFS_PIOCTL -DAFS_SETPAG -fPIC -c afssys.c -I/usr/local/krb5/include -Wall
	#magickou kontantu sem vycetl z /etc/name_to_sysnum
	gcc -DAFS_SYSCALL=65 -fPIC -c afssys.c -I/usr/include/krb5 -Wall
	ld -G -z text -o $(@) afssys.o

.c.o:
	$(CC) -c $(DEFINES) $(CFLAGS) $(INCLUDES) $<

install:
	mkdir $(DESTDIR)
	mkdir $(DESTDIR)/usr
	mkdir $(DESTDIR)/usr/bin
	mkdir $(DESTDIR)/usr/lib
	cp afsadm $(DESTDIR)/usr/bin
	cp afsadmd $(DESTDIR)/usr/bin
	cp libkafs.so $(DESTDIR)/usr/lib

clean:	
	rm -f $(CLNTOBJECTS) $(OBJECTS) libkafs.so afssys.o afsadm afsadmd
	rm -rf $(DESTDIR)

