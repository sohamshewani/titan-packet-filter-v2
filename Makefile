CXX ?= g++
CXXFLAGS ?= -std=c++17 -O3 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
LDFLAGS ?= 

TARGET := titan-packet-filter
SRC_DIR := src
BUILD_DIR := build
TEST_DIR := tests
BENCH_DIR := benchmarks

SRCS := $(wildcard $(SRC_DIR)/*.cpp)
OBJS := $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(SRCS))
DEPS := $(OBJS:.o=.d)

TEST_SRCS := $(wildcard $(TEST_DIR)/*.cpp)
BENCH_SRCS := $(wildcard $(BENCH_DIR)/*.cpp)

.PHONY: all build test clean benchmark directories

all: directories build

directories:
	@mkdir -p $(BUILD_DIR)

build: directories $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(OBJS)
	@if [ -n "$(OBJS)" ]; then \
		$(CXX) $(OBJS) -o $@ $(LDFLAGS); \
	else \
		echo "No source files found in $(SRC_DIR)/ to build target."; \
		exit 1; \
	fi

-include $(DEPS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

test: build
	@if [ -d "$(TEST_DIR)" ] && [ -n "$(TEST_SRCS)" ]; then \
		echo "Building and running tests..."; \
		$(CXX) $(CXXFLAGS) $(TEST_DIR)/*.cpp $(filter-out $(BUILD_DIR)/main.o, $(OBJS)) -o $(BUILD_DIR)/runner $(LDFLAGS) && \
		$(BUILD_DIR)/runner; \
	else \
		echo "No tests found in $(TEST_DIR)/. Skipping."; \
	fi

benchmark: build
	@if [ -d "$(BENCH_DIR)" ] && [ -n "$(BENCH_SRCS)" ]; then \
		echo "Building and running benchmarks..."; \
		$(CXX) $(CXXFLAGS) $(BENCH_DIR)/*.cpp $(filter-out $(BUILD_DIR)/main.o, $(OBJS)) -o $(BUILD_DIR)/benchmarker $(LDFLAGS) && \
		$(BUILD_DIR)/benchmarker; \
	else \
		echo "No benchmarks found in $(BENCH_DIR)/. Skipping."; \
	fi

clean:
	@rm -rf $(BUILD_DIR)
	@echo "Cleaned build artifacts."