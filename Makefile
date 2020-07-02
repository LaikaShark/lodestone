CXX=g++
OBJ=driver

.PHONY: all clean

all: $(OBJ)

lodestone.o: lodestone.cc
	$(CXX) -std=c++11 -c lodestone.cc

driver: lodestone.o driver.cc
	$(CXX) -std=c++11 -o driver driver.cc lodestone.o -lbfd

clean:
	rm -f $(OBJ) *.o

