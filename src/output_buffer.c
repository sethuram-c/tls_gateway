#include "output_buffer.h"

#include <string.h>

void output_buffer_init(OutputBuffer *buffer)
{
    if (buffer != NULL) {
        buffer->length = 0;
        buffer->offset = 0;
    }
}

size_t output_buffer_pending(const OutputBuffer *buffer)
{
    return buffer == NULL ? 0 : buffer->length - buffer->offset;
}

int output_buffer_enqueue(OutputBuffer *buffer, const void *data, size_t length)
{
    if (buffer == NULL || data == NULL || length == 0 ||
        length > OUTPUT_BUFFER_CAPACITY || output_buffer_pending(buffer) != 0) {
        return -1;
    }
    memcpy(buffer->data, data, length);
    buffer->length = length;
    buffer->offset = 0;
    return 0;
}

const unsigned char *output_buffer_data(const OutputBuffer *buffer)
{
    return buffer == NULL ? NULL : buffer->data + buffer->offset;
}

int output_buffer_consume(OutputBuffer *buffer, size_t length)
{
    if (buffer == NULL || length == 0 || length > output_buffer_pending(buffer)) {
        return -1;
    }
    buffer->offset += length;
    if (buffer->offset == buffer->length) output_buffer_init(buffer);
    return 0;
}
