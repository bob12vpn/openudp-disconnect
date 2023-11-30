TARGET=packet-sender
HDRDIR=./headers
SRCS=$(wildcard *.cpp) $(wildcard $(HDRDIR)/*.cpp)
OBJS=$(SRCS:%.cpp=%.o)

CPPFLAGS+=-Wall -Wextra -g
LDLIBS+=-lpcap

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET) $(OBJS) 

