BOFNAME := getloggedon
COMINCLUDE := -I common
LIBINCLUDE :=
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
CC=x86_64-w64-mingw32-clang

BOF:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c entry.c -DBOF
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c entry.c -DBOF
	mkdir -p bin/$(BOFNAME)
	mv $(BOFNAME)*.o bin/$(BOFNAME)

	# easy testing on CS
	cp -r bin/$(BOFNAME)/* /home/sh4rks/shared/getloggedon/
	cp getloggedon.cna /home/sh4rks/shared/getloggedon/

test:
	$(CC_x64) entry.c -g $(COMINCLUDE) $(LIBINCLUDE)  -o bin/$(BOFNAME).x64.exe
	$(CC_x86) entry.c -g $(COMINCLUDE) $(LIBINCLUDE) -o bin/$(BOFNAME).x86.exe

	cp -r bin/$(BOFNAME)* /home/sh4rks/shared/getloggedon/
	cp getloggedon.cna /home/sh4rks/shared/getloggedon/

scanbuild:
	$(CC) entry.c -o $(BOFNAME).scanbuild.exe $(COMINCLUDE) $(LIBINCLUDE)

check:
	cppcheck --enable=all $(COMINCLUDE) --platform=win64 entry.c

clean:
	rm $(BOFNAME).*.exe