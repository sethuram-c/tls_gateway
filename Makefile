CC := gcc
CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -Werror -g
CPPFLAGS := -Iinclude
TARGET := build/tls-gateway
OBJECTS := build/main.o build/log.o build/socket_demo.o build/nonblock_demo.o build/socket_flags.o build/tcp_server.o build/backend_connect.o build/tcp_proxy.o build/tls_context.o build/tls_listener.o build/tls_forward.o

.PHONY: all test clean certs
all: $(TARGET)
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ -lssl -lcrypto
build/main.o: src/main.c include/log.h include/socket_demo.h include/nonblock_demo.h include/tcp_server.h include/backend_connect.h include/tcp_proxy.h include/tls_context.h include/tls_listener.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/log.o: src/log.c include/log.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/socket_demo.o: src/socket_demo.c include/socket_demo.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/nonblock_demo.o: src/nonblock_demo.c include/nonblock_demo.h include/socket_flags.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/socket_flags.o: src/socket_flags.c include/socket_flags.h
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
build/tls_listener.o: src/tls_listener.c include/tls_listener.h include/tls_context.h include/tls_forward.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/tls_forward.o: src/tls_forward.c include/tls_forward.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/tls_context.o: src/tls_context.c include/tls_context.h
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
	python3 tests/test_tls_context.py
	python3 tests/test_tls_listener.py
	python3 tests/test_tls_read.py
	python3 tests/test_tls_write.py
	python3 tests/test_tls_proxy.py
	python3 tests/test_nonblock_demo.py
	python3 tests/test_socket_flags.py
certs:
	bash scripts/generate_dev_certs.sh
clean:
	rm -rf build
