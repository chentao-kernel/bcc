CC = gcc
CFLAGS = -Wall -Wextra -fPIC
LDFLAGS = -ldl -pthread

TARGET = mem_hook.so
TEST_APP = test_mem

all: $(TARGET) $(TEST_APP) mem_stat

$(TARGET): mem_hook.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS)

mem_stat: mem_stat.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS)


$(TEST_APP): test_mem.c
	$(CC) -Wall -o $@ $<

run: all
	@echo "--- Running test with LD_PRELOAD ---"
	LD_PRELOAD=./$(TARGET) ./$(TEST_APP)

clean:
	rm -f $(TARGET) $(TEST_APP) mem_stat

.PHONY: all clean run
