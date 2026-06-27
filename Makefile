CC := gcc
CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -Werror -g
CPPFLAGS := -Iinclude
TARGET := build/tls-gateway
OBJECTS := build/main.o build/log.o build/socket_demo.o build/nonblock_demo.o build/socket_flags.o build/epoll_demo.o build/epoll_server.o build/epoll_tls.o build/epoll_tls_proxy.o build/tls_state.o build/output_buffer.o build/connection.o build/tcp_server.o build/backend_connect.o build/backend_async.o build/tcp_proxy.o build/tls_context.o build/tls_listener.o build/tls_forward.o

.PHONY: all test clean certs certs-sni
all: $(TARGET)
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ -lssl -lcrypto
build/main.o: src/main.c include/log.h include/socket_demo.h include/nonblock_demo.h include/epoll_demo.h include/epoll_server.h include/epoll_tls.h include/epoll_tls_proxy.h include/tcp_server.h include/backend_async.h include/backend_connect.h include/tcp_proxy.h include/tls_context.h include/tls_listener.h
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
build/epoll_demo.o: src/epoll_demo.c include/epoll_demo.h include/socket_flags.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/epoll_server.o: src/epoll_server.c include/epoll_server.h include/connection.h include/socket_flags.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/epoll_tls.o: src/epoll_tls.c include/epoll_tls.h include/connection.h include/socket_flags.h include/tls_context.h include/output_buffer.h include/tls_state.h include/backend_async.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/epoll_tls_proxy.o: src/epoll_tls_proxy.c include/epoll_tls_proxy.h include/backend_async.h include/connection.h include/tls_context.h include/socket_flags.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/tls_state.o: src/tls_state.c include/tls_state.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/output_buffer.o: src/output_buffer.c include/output_buffer.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/connection.o: src/connection.c include/connection.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/tcp_server.o: src/tcp_server.c include/tcp_server.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/backend_connect.o: src/backend_connect.c include/backend_connect.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/backend_async.o: src/backend_async.c include/backend_async.h
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
	python3 tests/test_epoll_demo.py
	python3 tests/test_epoll_server.py
	python3 tests/test_connection_registry.py
	python3 tests/test_epoll_tls.py
	python3 tests/test_epoll_tls_read.py
	python3 tests/test_output_buffer.py
	python3 tests/test_epoll_tls_write.py
	python3 tests/test_tls_state.py
	python3 tests/test_epoll_backend.py
	python3 tests/test_epoll_tls_proxy.py
	python3 tests/test_sni_observation.py
certs:
	bash scripts/generate_dev_certs.sh
certs-sni:
	bash scripts/generate_sni_cert.sh
clean:
	rm -rf build
