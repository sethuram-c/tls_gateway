#ifndef OUTPUT_BUFFER_H
#define OUTPUT_BUFFER_H

#include <stddef.h>

/* Bounded, single-chunk output queue. No allocation or unbounded buffering.
 * Do not modify the queued data while SSL_write is awaiting retry. */
#define OUTPUT_BUFFER_CAPACITY 4096U

typedef struct {
    unsigned char data[OUTPUT_BUFFER_CAPACITY];
    size_t length;
    size_t offset;
} OutputBuffer;

void output_buffer_init(OutputBuffer *buffer);
size_t output_buffer_pending(const OutputBuffer *buffer);
/* Enqueue a chunk only when the previous chunk has drained. Returns 0 on success. */
int output_buffer_enqueue(OutputBuffer *buffer, const void *data, size_t length);
const unsigned char *output_buffer_data(const OutputBuffer *buffer);
/* Advance after a successful positive SSL_write; rejects invalid consumption. */
int output_buffer_consume(OutputBuffer *buffer, size_t length);

#endif
