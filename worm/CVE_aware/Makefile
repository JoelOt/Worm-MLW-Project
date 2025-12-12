CC = gcc
CFLAGS = -Wall -Wextra -std=c11
TARGET = worm_cve_aware
BUILD_DIR = build

# Source files
SOURCES = worm_cve_aware.c \
          utils.c \
          state_manager.c \
          risk_assessment.c \
          handler_registry.c \
          decision_engine.c \
          degradation.c

# Object files (in build directory)
OBJECTS = $(SOURCES:%.c=$(BUILD_DIR)/%.o)

# Default target
all: $(BUILD_DIR)/$(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build target
$(BUILD_DIR)/$(TARGET): $(OBJECTS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS)

# Compile object files
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -rf $(BUILD_DIR)

# Phony targets
.PHONY: all clean

