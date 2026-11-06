/*
 * Simplified training copy of string helpers from a 7.2-era interpreter.
 * Part of the LegacyGuard test data: not the real PHP source.
 */

#include <stdlib.h>
#include <string.h>
#include "php.h"

#define STR_PAD_LEFT  0
#define STR_PAD_RIGHT 1
#define STR_PAD_BOTH  2

char *php_strtoupper(char *s, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (s[i] >= 'a' && s[i] <= 'z')
            s[i] -= 'a' - 'A';
    return s;
}

char *php_str_repeat(const char *input, size_t input_len, size_t mult)
{
    char *result;

    if (mult == 0 || input_len == 0)
        return estrdup("");
    result = emalloc(input_len * mult + 1);
    for (size_t i = 0; i < mult; i++)
        memcpy(result + i * input_len, input, input_len);
    result[input_len * mult] = '\0';
    return result;
}

char *php_str_pad(const char *input, size_t input_len, size_t pad_length,
                  const char *pad_str, size_t pad_str_len, int pad_type)
{
    size_t num_pad_chars, left_pad = 0, right_pad = 0, i;
    char *result;
    size_t result_len = 0;

    if (pad_length <= input_len)
        return estrndup(input, input_len);

    if (pad_type < STR_PAD_LEFT || pad_type > STR_PAD_BOTH) {
        php_error_docref(NULL, E_WARNING, "Padding type has to be STR_PAD_LEFT, "
                         "STR_PAD_RIGHT, or STR_PAD_BOTH");
        return NULL;
    }

    num_pad_chars = pad_length - input_len;
    result = emalloc(input_len + num_pad_chars + 1);

    switch (pad_type) {
    case STR_PAD_RIGHT:
        left_pad = 0;
        right_pad = num_pad_chars;
        break;
    case STR_PAD_LEFT:
        left_pad = num_pad_chars;
        right_pad = 0;
        break;
    case STR_PAD_BOTH:
        left_pad = num_pad_chars / 2;
        right_pad = num_pad_chars - left_pad;
        break;
    }

    for (i = 0; i < left_pad; i++)
        result[result_len++] = pad_str[i % pad_str_len];
    memcpy(result + result_len, input, input_len);
    result_len += input_len;
    for (i = 0; i < right_pad; i++)
        result[result_len++] = pad_str[i % pad_str_len];
    result[result_len] = '\0';

    return result;
}
