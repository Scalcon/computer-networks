# Nome do executável final
TARGET = server

# Compilador C++
CXX = g++

CXXFLAGS = -std=c++11 -Wall -Wextra -O2 -pthread -g

SRCS = tcp_server.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(CXXFLAGS) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)