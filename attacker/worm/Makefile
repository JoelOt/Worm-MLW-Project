CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = worm
SOURCE = worm.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

.PHONY: all clean

