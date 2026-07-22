CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LIBS = -lpcap

SRC = src/main.c src/sniffer.c src/protocol_parser.c
OBJ = $(SRC:.c=.o)
TARGET = sniffer

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)

.PHONY: all clean