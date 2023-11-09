CPPFLAGS = -Wno-deprecated -pthread -D__LINUX__  -D__ANDROID__  -D_SPLIT_USE_NEWALLOC -lrt -std=c++11 -lssl -lcrypto -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv

OBJECTS = IFOMServer.o Setup.o LinuxTun.o

IFOMServer : $(OBJECTS)
	g++ -g $(OBJECTS) -o gmaserver $(CPPFLAGS)


IFOMServer.o : IFOMServer.cpp
	g++ -c -g IFOMServer.cpp -o IFOMServer.o $(CPPFLAGS)

Setup.o : Setup.cpp
	g++ -c -g Setup.cpp -o Setup.o $(CPPFLAGS)

LinuxTun.o : LinuxTun.cpp
	g++ -c -g LinuxTun.cpp -o LinuxTun.o $(CPPFLAGS)

.PHONY: clean

clean:
	rm -f *.o i *.log* core
