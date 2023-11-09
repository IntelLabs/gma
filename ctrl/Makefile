CPPFLAGS =  -pthread -std=c++11 -Wformat-overflow

MeasurementReport : $(OBJECTS)
	g++ -g MeasurementReport.cpp -o gmactl $(CPPFLAGS)

.PHONY: clean

clean:
	rm -f *.o i *.log* core
