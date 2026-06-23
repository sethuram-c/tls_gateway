#include "output_buffer.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    OutputBuffer queue;
    const unsigned char source[] = {0, 65, 255, 10, 0};
    output_buffer_init(&queue);
    assert(output_buffer_pending(&queue) == 0);
    assert(output_buffer_enqueue(&queue, source, sizeof(source)) == 0);
    assert(output_buffer_pending(&queue) == sizeof(source));
    assert(memcmp(output_buffer_data(&queue), source, sizeof(source)) == 0);
    /* The send operation can stop after two bytes; remaining bytes persist. */
    assert(output_buffer_consume(&queue, 2) == 0);
    assert(output_buffer_pending(&queue) == 3);
    assert(memcmp(output_buffer_data(&queue), source + 2, 3) == 0);
    /* Backpressure: never overwrite bytes not yet written. */
    assert(output_buffer_enqueue(&queue, source, 1) == -1);
    assert(output_buffer_consume(&queue, 4) == -1);
    assert(output_buffer_pending(&queue) == 3);
    assert(output_buffer_consume(&queue, 3) == 0);
    assert(output_buffer_pending(&queue) == 0);
    assert(output_buffer_enqueue(&queue, source, sizeof(source)) == 0);
    assert(output_buffer_enqueue(&queue, source, 1) == -1);
    output_buffer_init(&queue);
    unsigned char oversized[OUTPUT_BUFFER_CAPACITY + 1] = {0};
    assert(output_buffer_enqueue(&queue, oversized, sizeof(oversized)) == -1);
    assert(output_buffer_consume(&queue, 1) == -1);
    assert(output_buffer_enqueue(&queue, source, 0) == -1);
    puts("PASS: partial writes, pending data, queue bounds and backpressure");
    return 0;
}
