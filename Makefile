TARGET = main
SRCS = main.cpp sh256.cu

SRCS_FILES = $(foreach F, $(SRCS), ./$(F))
CXX_FLAGS = -lpthread -lm -O3 -g -lcuda -lcudart

all : main.o sh256.o
	nvcc $(CXX_FLAGS) main.o sh256.o -o $(TARGET)


main.o: main.cpp
	nvcc $(CXX_FLAGS) main.cpp -c
    
sh256.o: sh256.cu
	nvcc $(CXX_FLAGS) sh256.cu -c

clean :
	@rm -f *.o $(TARGET)