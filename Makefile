DEBUG := FALSE
CC  = gcc
CXX = g++

GCCFLAGS = -Wall -W -Wextra $(shell pkg-config --cflags libusbgx) -std=c++17 -Wno-unused-parameter -Wno-unused-variable
LDFLAGS = -pthread -lusbredirparser $(shell pkg-config --libs libusbgx)

ifeq ($(DEBUG),FALSE)
	GCCFLAGS += -Os -D NDEBUG
else
	GCCFLAGS += -O0 -g
endif

OBJS = $(patsubst %.c, %.o, $(shell find . -name \*.c))
OBJS += $(patsubst %.cpp, %.o, $(shell find . -name \*.cpp))
EXE = usbredir2phys

all: $(EXE)

%.o: %.c
	$(CC) $(GCCFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(GCCFLAGS) -c $< -o $@
	
%.o: %.S
	$(AS) -c $< -o $@

$(EXE): $(OBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(EXE)
