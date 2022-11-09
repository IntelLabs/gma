# all :
# 	source Client
CPPFLAGS = -std=c++11 -lcrypto -lssl -lboost_system  -pthread

OBJECTS = Client.o ServiceManager.o SystemStateSettings.o Methods.o

# source : 
# 	cd lib && $(MAKE)

# .PHONY : Client

Client : $(OBJECTS)
	g++ -g $(OBJECTS) libgma.a -o gmaclient $(CPPFLAGS)
 
Client.o : client.cpp
	g++ -c -g client.cpp -o Client.o $(CPPFLAGS)

ServiceManager.o : ServiceManager.cpp
	g++ -c -g ServiceManager.cpp -o ServiceManager.o $(CPPFLAGS)

SystemStateSettings.o : SystemStateSettings.cpp
	g++ -c -g SystemStateSettings.cpp -o SystemStateSettings.o $(CPPFLAGS)

Methods.o : Methods.cpp
	g++ -c -g Methods.cpp -o Methods.o $(CPPFLAGS)

.PHONY: clean

clean:
	rm -f *.o *.a i *.log* core && cd lib && rm -f *.o *.a i *.log* core
