CC := gcc
CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -Werror -g
CPPFLAGS := -Iinclude
TARGET := build/tls-gateway
OBJECTS := build/main.o build/log.o build/socket_demo.o build/tcp_server.o build/backend_connect.o build/tcp_proxy.o

.PHONY: all test clean certs
all: $(TARGET)
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@
build/main.o: src/main.c include/log.h include/socket_demo.h include/tcp_server.h include/backend_connect.h include/tcp_proxy.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/log.o: src/log.c include/log.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/socket_demo.o: src/socket_demo.c include/socket_demo.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/tcp_server.o: src/tcp_server.c include/tcp_server.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/backend_connect.o: src/backend_connect.c include/backend_connect.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/tcp_proxy.o: src/tcp_proxy.c include/tcp_proxy.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
test: $(TARGET)
	python3 tests/smoke_test.py
	python3 tests/test_tcp_server.py
	python3 tests/test_http_backend.py
	python3 tests/test_backend_connect.py
	python3 tests/test_tcp_proxy.py
	python3 tests/test_tls_handshake.py
	python3 tests/test_certificates.py
certs:
	bash scripts/generate_dev_certs.sh
clean:
	rm -rf build
