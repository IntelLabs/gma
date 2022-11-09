CPPFLAGS = -std=c++11 -lcrypto -lssl -lboost_system  -pthread

OBJECTS = libgma.a

libgma.a : EncryptorAesGcm.o Header.o ConnectServer.o Common.o ConnectionMessages.o ControlMessage.o DataReceive.o DataSend.o Measurement.o ReorderingManager.o VirtualWebsockets.o TcpReceive.o
	ar rcs $@ $^ && mv libgma.a ../../client/
 
Common.o : Common.cpp
	g++ -c -g Common.cpp -o Common.o $(CPPFLAGS)
 
ConnectionMessages.o : ConnectionMessages.cpp
	g++ -c -g ConnectionMessages.cpp -o ConnectionMessages.o $(CPPFLAGS)

ConnectServer.o : ConnectServer.cpp
	g++ -c -g ConnectServer.cpp -o ConnectServer.o $(CPPFLAGS)

ControlMessage.o : ControlMessage.cpp
	g++ -c -g ControlMessage.cpp -o ControlMessage.o $(CPPFLAGS)

EncryptorAesGcm.o : EncryptorAesGcm.cpp
	g++ -c -g EncryptorAesGcm.cpp -o EncryptorAesGcm.o $(CPPFLAGS)

Header.o : Header.cpp
	g++ -c -g Header.cpp -o Header.o $(CPPFLAGS)

DataSend.o : DataSend.cpp
	g++ -c -g DataSend.cpp -o DataSend.o $(CPPFLAGS)

DataReceive.o : DataReceive.cpp
	g++ -c -g DataReceive.cpp -o DataReceive.o $(CPPFLAGS)

Measurement.o : Measurement.cpp
	g++ -c -g Measurement.cpp -o Measurement.o $(CPPFLAGS)

ReorderingManager.o : ReorderingManager.cpp
	g++ -c -g ReorderingManager.cpp -o ReorderingManager.o $(CPPFLAGS)

VirtualWebsockets.o : VirtualWebsockets.cpp
	g++ -c -g VirtualWebsockets.cpp -o VirtualWebsockets.o $(CPPFLAGS)

TcpReceive.o : TcpReceive.cpp
	g++ -c -g TcpReceive.cpp -o TcpReceive.o $(CPPFLAGS)


.PHONY: clean

clean:
	rm -f *.o *.a i *.log* core
