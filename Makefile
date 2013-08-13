#Makefile for Open Patcher
#Tested to compile under MinGW and Linux based GNU make

TARGET = op
BUILD_PATH = bin
FLAGS = -std=c++11 -fpermissive -w -static-libgcc -static-libstdc++


OBJS = \
 $(patsubst %.cpp, %.o, $(wildcard *.cpp)) \
 $(patsubst %.cpp, %.o, $(wildcard patchers/*.cpp))

BUILD_FILES = $(BUILD_PATH)/$(TARGET) $(OBJS)

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BUILD_PATH)
	g++ $(FLAGS) -o $(BUILD_PATH)/$@ $^


%.o: %.cpp
	g++ $(FLAGS) -o $@ -c $<


clean:
	rm -f $(BUILD_FILES)
