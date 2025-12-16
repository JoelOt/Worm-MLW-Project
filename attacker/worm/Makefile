CC = gcc
# Mantienes C11 y tienes todas las funciones POSIX disponibles.
CFLAGS = -Wall -Wextra -std=gnu11
TARGET = worm
SOURCES = worm.c cve_2025_32463.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)

.PHONY: all clean
