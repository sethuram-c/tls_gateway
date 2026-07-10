CC := gcc
CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -Werror -g
CPPFLAGS := -Iinclude
BUILD_DIR ?= build
TARGET := $(BUILD_DIR)/tls-gateway
OBJECTS := $(BUILD_DIR)/gateway_config.o $(BUILD_DIR)/main.o $(BUILD_DIR)/log.o $(BUILD_DIR)/socket_demo.o $(BUILD_DIR)/nonblock_demo.o $(BUILD_DIR)/socket_flags.o $(BUILD_DIR)/epoll_demo.o $(BUILD_DIR)/epoll_server.o $(BUILD_DIR)/epoll_tls.o $(BUILD_DIR)/epoll_tls_proxy.o $(BUILD_DIR)/sni_select.o $(BUILD_DIR)/mtls.o $(BUILD_DIR)/tls_credentials.o $(BUILD_DIR)/tls_state.o $(BUILD_DIR)/output_buffer.o $(BUILD_DIR)/connection.o $(BUILD_DIR)/tcp_server.o $(BUILD_DIR)/backend_connect.o $(BUILD_DIR)/backend_async.o $(BUILD_DIR)/tcp_proxy.o $(BUILD_DIR)/tls_context.o $(BUILD_DIR)/tls_listener.o $(BUILD_DIR)/tls_forward.o

.PHONY: all debug asan ubsan test-sanitize test test-list test-runner test-smoke test-resources test-timeouts test-drain test-edge test-bench bench clean certs certs-sni certs-client
all: $(TARGET)
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ -lssl -lcrypto
$(BUILD_DIR)/main.o: src/main.c include/gateway_config.h include/log.h include/socket_demo.h include/nonblock_demo.h include/epoll_demo.h include/epoll_server.h include/epoll_tls.h include/epoll_tls_proxy.h include/tcp_server.h include/backend_async.h include/backend_connect.h include/tcp_proxy.h include/tls_context.h include/tls_listener.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/gateway_config.o: src/gateway_config.c include/gateway_config.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/log.o: src/log.c include/log.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/socket_demo.o: src/socket_demo.c include/socket_demo.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/nonblock_demo.o: src/nonblock_demo.c include/nonblock_demo.h include/socket_flags.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/socket_flags.o: src/socket_flags.c include/socket_flags.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/epoll_demo.o: src/epoll_demo.c include/epoll_demo.h include/socket_flags.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/epoll_server.o: src/epoll_server.c include/epoll_server.h include/connection.h include/socket_flags.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/epoll_tls.o: src/epoll_tls.c include/epoll_tls.h include/connection.h include/socket_flags.h include/tls_context.h include/output_buffer.h include/tls_state.h include/backend_async.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/epoll_tls_proxy.o: src/epoll_tls_proxy.c include/epoll_tls_proxy.h include/backend_async.h include/connection.h include/tls_context.h include/socket_flags.h include/sni_select.h include/mtls.h include/tls_credentials.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/tls_credentials.o: src/tls_credentials.c include/tls_credentials.h include/tls_context.h include/mtls.h include/sni_select.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/mtls.o: src/mtls.c include/mtls.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/sni_select.o: src/sni_select.c include/sni_select.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/tls_state.o: src/tls_state.c include/tls_state.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/output_buffer.o: src/output_buffer.c include/output_buffer.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/connection.o: src/connection.c include/connection.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/tcp_server.o: src/tcp_server.c include/tcp_server.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/backend_connect.o: src/backend_connect.c include/backend_connect.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/backend_async.o: src/backend_async.c include/backend_async.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/tcp_proxy.o: src/tcp_proxy.c include/tcp_proxy.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/tls_listener.o: src/tls_listener.c include/tls_listener.h include/tls_context.h include/tls_forward.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/tls_forward.o: src/tls_forward.c include/tls_forward.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD_DIR)/tls_context.o: src/tls_context.c include/tls_context.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
# Integration runner discovers smoke_test.py and all test_*.py scripts.
# Each script runs in an isolated process group with a per-test deadline.
test: $(TARGET)
	python3 tests/verify_test_runner.py
	python3 tests/run_tests.py
test-list:
	python3 tests/run_tests.py --list
test-runner:
	python3 tests/verify_test_runner.py
test-smoke: $(TARGET)
	python3 tests/run_tests.py --match smoke
# Run the slower process-level leak/cleanup regression on demand.
test-resources: $(TARGET)
	python3 tests/test_resource_cleanup.py
# Run the deadline/idle test on demand (about 20 seconds).
test-timeouts: $(TARGET)
	python3 tests/test_connection_timeouts.py
test-drain: $(TARGET)
	python3 tests/test_graceful_shutdown.py
certs:
	bash scripts/generate_dev_certs.sh
certs-sni:
	bash scripts/generate_sni_cert.sh
certs-client:
	bash scripts/generate_client_cert.sh
clean:
	rm -rf build build-asan build-ubsan
# Phase 39: malformed HTTP, disconnect, and slow-backend failure injection.
test-edge: $(TARGET)
	python3 tests/test_failure_injection.py

# Phase 40: isolated build directories prevent instrumented objects from
# silently contaminating the normal build (or vice versa).
# The same C sources are compiled with the different instrumentation flags.
SAN_COMMON := -std=c17 -Wall -Wextra -Wpedantic -Werror -g3 -O1 -fno-omit-frame-pointer

# Debug symbols are already included in the default build (-g).
debug: all
	@echo "GDB symbols available in $(TARGET)"

asan:
	$(MAKE) BUILD_DIR=build-asan CFLAGS="$(SAN_COMMON) -fsanitize=address -fno-sanitize-recover=all" LDFLAGS="-fsanitize=address"

ubsan:
	$(MAKE) BUILD_DIR=build-ubsan CFLAGS="$(SAN_COMMON) -fsanitize=undefined -fno-sanitize-recover=all" LDFLAGS="-fsanitize=undefined"

test-sanitize: asan ubsan
	python3 tests/verify_sanitizers.py

# Phase 41: benchmark uses verified TLS 1.3 against a running LOCAL gateway.
# Start tests/http_backend.py and --epoll-tls-proxy separately first.
# Machine-specific measurements are ignored by Git.
bench: $(TARGET)
	python3 bench/https_bench.py --ca certs/ca.crt --port 18444 --requests 200 --concurrency 4 --warmup 20 --json-out bench_results/phase41-c4.json

test-bench: $(TARGET)
	python3 tests/test_https_benchmark.py
