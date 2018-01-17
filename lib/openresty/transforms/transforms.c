#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/**
 * NOTE: Be careful as these can ONLY be used on static values for X.
 * (i.e. VALID_HEX(c++) will NOT work)
 */
#define VALID_HEX(X) (((X >= '0')&&(X <= '9')) || ((X >= 'a')&&(X <= 'f')) || ((X >= 'A')&&(X <= 'F')))
#define ISODIGIT(X) ((X >= '0')&&(X <= '7'))

#define UNICODE_ERROR_CHARACTERS_MISSING    -1
#define UNICODE_ERROR_INVALID_ENCODING      -2

#define NBSP                                 160

/**
 * Converts a byte given as its hexadecimal representation
 * into a proper byte. Handles uppercase and lowercase letters
 * but does not check for overflows.
 */
static unsigned char x2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

    return digit;
}

/**
 * Converts a single hexadecimal digit into a decimal value.
 */
static unsigned char xsingle2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));

    return digit;
}

/**
 * JavaScript decoding.
 * IMP1 Assumes NUL-terminated
 */
int js_decode(unsigned char *input, long int input_len) {

    unsigned char *d = (unsigned char *)input;
    long int i, count;

    if (input == NULL) return -1;

    i = count = 0;
    while (i < input_len) {
        if (input[i] == '\\') {
            /* Character is an escape. */

            if (   (i + 5 < input_len) && (input[i + 1] == 'u')
                    && (VALID_HEX(input[i + 2])) && (VALID_HEX(input[i + 3]))
                    && (VALID_HEX(input[i + 4])) && (VALID_HEX(input[i + 5])) )
            {
                /* \uHHHH */

                /* Use only the lower byte. */
                *d = x2c(&input[i + 4]);

                /* Full width ASCII (ff01 - ff5e) needs 0x20 added */
                if (   (*d > 0x00) && (*d < 0x5f)
                        && ((input[i + 2] == 'f') || (input[i + 2] == 'F'))
                        && ((input[i + 3] == 'f') || (input[i + 3] == 'F')))
                {
                    (*d) += 0x20;
                }

                d++;
                count++;
                i += 6;
            }
            else if (   (i + 3 < input_len) && (input[i + 1] == 'x')
                    && VALID_HEX(input[i + 2]) && VALID_HEX(input[i + 3])) {
                /* \xHH */
                *d++ = x2c(&input[i + 2]);
                count++;
                i += 4;
            }
            else if ((i + 1 < input_len) && ISODIGIT(input[i + 1])) {
                /* \OOO (only one byte, \000 - \377) */
                char buf[4];
                int j = 0;

                while((i + 1 + j < input_len)&&(j < 3)) {
                    buf[j] = input[i + 1 + j];
                    j++;
                    if (!ISODIGIT(input[i + 1 + j])) break;
                }
                buf[j] = '\0';

                if (j > 0) {
                    /* Do not use 3 characters if we will be > 1 byte */
                    if ((j == 3) && (buf[0] > '3')) {
                        j = 2;
                        buf[j] = '\0';
                    }
                    *d++ = (unsigned char)strtol(buf, NULL, 8);
                    i += 1 + j;
                    count++;
                }
            }
            else if (i + 1 < input_len) {
                /* \C */
                unsigned char c = input[i + 1];
                switch(input[i + 1]) {
                    case 'a' :
                        c = '\a';
                        break;
                    case 'b' :
                        c = '\b';
                        break;
                    case 'f' :
                        c = '\f';
                        break;
                    case 'n' :
                        c = '\n';
                        break;
                    case 'r' :
                        c = '\r';
                        break;
                    case 't' :
                        c = '\t';
                        break;
                    case 'v' :
                        c = '\v';
                        break;
                        /* The remaining (\?,\\,\',\") are just a removal
                         * of the escape char which is default.
                         */
                }

                *d++ = c;
                i += 2;
                count++;
            }
            else {
                /* Not enough bytes */
                while(i < input_len) {
                    *d++ = input[i++];
                    count++;
                }
            }
        }
        else {
            *d++ = input[i++];
            count++;
        }
    }

    *d = '\0';

	return d - input;
}

/**
 * Decode a string that contains CSS-escaped characters.
 * 
 * References:
 *     http://www.w3.org/TR/REC-CSS2/syndata.html#q4
 *     http://www.unicode.org/roadmaps/
 */
int css_decode(unsigned char *input, long int input_len) {

    unsigned char *d = (unsigned char *)input;
    long int i, j, count;

    if (input == NULL) return -1;

    i = count = 0;
    while (i < input_len) {

        /* Is the character a backslash? */
        if (input[i] == '\\') {

            /* Is there at least one more byte? */
            if (i + 1 < input_len) {
                i++; /* We are not going to need the backslash. */

                /* Check for 1-6 hex characters following the backslash */
                j = 0;
                while (    (j < 6)
                        && (i + j < input_len)
                        && (VALID_HEX(input[i + j])))
                {
                    j++;
                }

                if (j > 0) { /* We have at least one valid hexadecimal character. */
                    int fullcheck = 0;

                    /* For now just use the last two bytes. */
                    switch (j) {
                        /* Number of hex characters */
                        case 1:
                            *d++ = xsingle2c(&input[i]);
                            break;

                        case 2:
                        case 3:
                            /* Use the last two from the end. */
                            *d++ = x2c(&input[i + j - 2]);
                            break;

                        case 4:
                            /* Use the last two from the end, but request
                             * a full width check.
                             */
                            *d = x2c(&input[i + j - 2]);
                            fullcheck = 1;
                            break;

                        case 5:
                            /* Use the last two from the end, but request
                             * a full width check if the number is greater
                             * or equal to 0xFFFF.
                             */
                            *d = x2c(&input[i + j - 2]);

                            /* Do full check if first byte is 0 */
                            if (input[i] == '0') {
                                fullcheck = 1;
                            }
                            else {
                                d++;
                            }
                            break;

                        case 6:
                            /* Use the last two from the end, but request
                             * a full width check if the number is greater
                             * or equal to 0xFFFF.
                             */
                            *d = x2c(&input[i + j - 2]);

                            /* Do full check if first/second bytes are 0 */
                            if (    (input[i] == '0')
                                    && (input[i + 1] == '0')
                               ) {
                                fullcheck = 1;
                            }
                            else {
                                d++;
                            }
                            break;
                    }

                    /* Full width ASCII (0xff01 - 0xff5e) needs 0x20 added */
                    if (fullcheck) {
                        if (   (*d > 0x00) && (*d < 0x5f)
                                && ((input[i + j - 3] == 'f') ||
                                    (input[i + j - 3] == 'F'))
                                && ((input[i + j - 4] == 'f') ||
                                    (input[i + j - 4] == 'F')))
                        {
                            (*d) += 0x20;
                        }

                        d++;
                    }

                    /* We must ignore a single whitespace after a hex escape */
                    if ((i + j < input_len) && isspace(input[i + j])) {
                        j++;
                    }

                    /* Move over. */
                    count++;
                    i += j;
                }

                /* No hexadecimal digits after backslash */
                else if (input[i] == '\n') {
                    /* A newline character following backslash is ignored. */
                    i++;
                }

                /* The character after backslash is not a hexadecimal digit, nor a newline. */
                else {
                    /* Use one character after backslash as is. */
                    *d++ = input[i++];
                    count++;
                }
            }

            /* No characters after backslash. */
            else {
                /* Do not include backslash in output (continuation to nothing) */
                i++; 
            }
        }

        /* Character is not a backslash. */
        else {
            /* Copy one normal character to output. */
            *d++ = input[i++];
            count++;
        }
    }

    /* Terminate output string. */
    *d = '\0';

    return d - input;
}


/* Base64 tables used in decodeBase64Ext */
static const char b64_pad = '=';

static const short b64_reverse_t[256] = {
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -2, -1, -2, -2,
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
  -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
  -2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
  -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
  -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
};

/** 
 * \brief Decode Base64 data with special chars
 * \param plain_text Pointer to plain text data
 * \param input Pointer to input data
 * \param input_len Input data length
 *
 * \retval 0 On failure
 * \retval string length On Success
 */
int decode_base64_ext(char *plain_text, const unsigned char *input, int input_len) {
    const unsigned char *encoded = input;
    int i = 0, j = 0, k = 0;
    int ch = 0;

    while ((ch = *encoded++) != '\0' && input_len-- > 0) {
        if (ch == b64_pad) {
            if (*encoded != '=' && (i % 4) == 1) {
                return 0;
            }
            continue;
        }

        ch = b64_reverse_t[ch];
        if (ch < 0 || ch == -1) {
            continue;
        } else if (ch == -2) {
            return 0;
        }
        switch(i % 4) {
            case 0:
                plain_text[j] = ch << 2;
                break;
            case 1:
                plain_text[j++] |= ch >> 4;
                plain_text[j] = (ch & 0x0f) << 4;
                break;
            case 2:
                plain_text[j++] |= ch >>2;
                plain_text[j] = (ch & 0x03) << 6;
                break;
            case 3:
                plain_text[j++] |= ch;
                break;
        }
        i++;
    }

    k = j;
    if (ch == b64_pad) {
        switch(i % 4) {
            case 1:
                return 0;
            case 2:
                k++;
            case 3:
                plain_text[k] = 0;
        }
    }

    plain_text[j] = '\0';

    return j;
}


/**
 *
 * IMP1 Assumes NUL-terminated
 */
int escape_seq_decode(unsigned char *input, int input_len) {
    unsigned char *d = input;
    int i, count;

    i = count = 0;
    while(i < input_len) {
        if ((input[i] == '\\')&&(i + 1 < input_len)) {
            int c = -1;

            switch(input[i + 1]) {
                case 'a' :
                    c = '\a';
                    break;
                case 'b' :
                    c = '\b';
                    break;
                case 'f' :
                    c = '\f';
                    break;
                case 'n' :
                    c = '\n';
                    break;
                case 'r' :
                    c = '\r';
                    break;
                case 't' :
                    c = '\t';
                    break;
                case 'v' :
                    c = '\v';
                    break;
                case '\\' :
                    c = '\\';
                    break;
                case '?' :
                    c = '?';
                    break;
                case '\'' :
                    c = '\'';
                    break;
                case '"' :
                    c = '"';
                    break;
            }

            if (c != -1) i += 2;

            /* Hexadecimal or octal? */
            if (c == -1) {
                if ((input[i + 1] == 'x')||(input[i + 1] == 'X')) {
                    /* Hexadecimal. */
                    if ((i + 3 < input_len)&&(isxdigit(input[i + 2]))&&(isxdigit(input[i + 3]))) {
                        /* Two digits. */
                        c = x2c(&input[i + 2]);
                        i += 4;
                    } else {
                        /* Invalid encoding, do nothing. */
                    }
                }
                else
                    if (ISODIGIT(input[i + 1])) { /* Octal. */
                        char buf[4];
                        int j = 0;

                        while((i + 1 + j < input_len)&&(j < 3)) {
                            buf[j] = input[i + 1 + j];
                            j++;
                            if (!ISODIGIT(input[i + 1 + j])) break;
                        }
                        buf[j] = '\0';

                        if (j > 0) {
                            c = strtol(buf, NULL, 8);
                            i += 1 + j;
                        }
                    }
            }

            if (c == -1) {
                /* Didn't recognise encoding, copy raw bytes. */
                *d++ = input[i + 1];
                count++;
                i += 2;
            } else {
                /* Converted the encoding. */
                *d++ = c;
                count++;
            }
        } else {
            /* Input character not a backslash, copy it. */
            *d++ = input[i++];
            count++;
        }
    }

    *d = '\0';

    return count;
}


/** \brief Decode utf-8 to unicode format.
 *
 * \param output Pointer to memory pool
 * \param input Pointer to input data
 * \param input_len Input data length
 * \param changed Set if data is changed
 *
 * \retval rval On Success
 */

int utf8_to_unicode(char *output, unsigned char *input, long int input_len, unsigned char *changed) {
    int unicode_len = 0, length = 0;
    unsigned int d = 0, count = 0;
    unsigned char c, *utf;
    char *rval, *data;
    unsigned int i, len;
    unsigned int bytes_left = input_len;
    
    changed[0] = '0';
    len = input_len * 7 + 1;
    data = rval = (char *)malloc(len);
    
    if (rval == NULL) return 0;
    if (input == NULL) return 0;
    
    for(i = 0; i < bytes_left;)  {
        unicode_len = 0; d = 0;
        utf = (unsigned char *)&input[i];
        
        c = *utf;
        
        /* If first byte begins with binary 0 it is single byte encoding */
        if ((c & 0x80) == 0) {
            /* single byte unicode (7 bit ASCII equivilent) has no validation */
            count++;
            if(count <= len)    {
                if(c == 0)
                    *data = x2c(&c);
                else
                    *data++ = c;
            }
        }
        /* If first byte begins with binary 110 it is two byte encoding*/
        else if ((c & 0xE0) == 0xC0) {
            /* check we have at least two bytes */
            if (bytes_left < 2) unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            /* check second byte starts with binary 10 */
            else if (((*(utf + 1)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            else {
                unicode_len = 2;
                count+=6;
                if(count <= len) {
                    /* compute character number */
                    d = ((c & 0x1F) << 6) | (*(utf + 1) & 0x3F);
                    *data++ = '%';
                    *data++ = 'u';
                    length = sprintf(data, "%04x", d);
                    data += length;
                    
                    changed[0] = '1';
                }
            }
        }
        /* If first byte begins with binary 1110 it is three byte encoding */
        else if ((c & 0xF0) == 0xE0) {
            /* check we have at least three bytes */
            if (bytes_left < 3) unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            /* check second byte starts with binary 10 */
            else if (((*(utf + 1)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            /* check third byte starts with binary 10 */
            else if (((*(utf + 2)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            else {
                unicode_len = 3;
                count+=6;
                if(count <= len) {
                    /* compute character number */
                    d = ((c & 0x0F) << 12) | ((*(utf + 1) & 0x3F) << 6) | (*(utf + 2) & 0x3F);
                    *data++ = '%';
                    *data++ = 'u';
                    length = sprintf(data, "%04x", d);
                    data += length;
                    
                    changed[0] = '1';
                }
            }
        }
        /* If first byte begins with binary 11110 it is four byte encoding */
        else if ((c & 0xF8) == 0xF0) {
            /* restrict characters to UTF-8 range (U+0000 - U+10FFFF)*/
            if (c >= 0xF5) {
                *data++ = c;
            }
            /* check we have at least four bytes */
            if (bytes_left < 4) unicode_len = UNICODE_ERROR_CHARACTERS_MISSING;
            /* check second byte starts with binary 10 */
            else if (((*(utf + 1)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            /* check third byte starts with binary 10 */
            else if (((*(utf + 2)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            /* check forth byte starts with binary 10 */
            else if (((*(utf + 3)) & 0xC0) != 0x80) unicode_len = UNICODE_ERROR_INVALID_ENCODING;
            else {
                unicode_len = 4;
                count+=7;
                if(count <= len) {
                    /* compute character number */
                    d = ((c & 0x07) << 18) | ((*(utf + 1) & 0x3F) << 12) | ((*(utf + 2) & 0x3F) << 6) | (*(utf + 3) & 0x3F);
                    *data++ = '%';
                    *data++ = 'u';
                    length = sprintf(data, "%04x", d);
                    data += length;
                    
                    changed[0] = '1';
                }
            }
        }
        /* any other first byte is invalid (RFC 3629) */
        else {
            count++;
            if(count <= len)
                *data++ = c;
        }
        
        /* invalid UTF-8 character number range (RFC 3629) */
        if ((d >= 0xD800) && (d <= 0xDFFF)) {
            count++;
            if(count <= len)
                *data++ = c;
        }
        
        /* check for overlong */
        if ((unicode_len == 4) && (d < 0x010000)) {
            /* four byte could be represented with less bytes */
            count++;
            if(count <= len)
                *data++ = c;
        }
        else if ((unicode_len == 3) && (d < 0x0800)) {
            /* three byte could be represented with less bytes */
            count++;
            if(count <= len)
                *data++ = c;
        }
        else if ((unicode_len == 2) && (d < 0x80)) {
            /* two byte could be represented with less bytes */
            count++;
            if(count <= len)
                *data++ = c;
        }
        
        if(unicode_len > 0) {
            i += unicode_len;
        } else {
            i++;
        }
    }
    
    *data ='\0';
    memcpy(output, rval, data - rval);
    length = data - rval;
    free(rval);
    
    return length;
}

/* cmdline */

/**
* \brief cmdline transformation function
*
* \param input Pointer to input data
* \param input_len Input data length
*
* \retval output_len
*/
int cmdline_execute(unsigned char *input, long int input_len)
{
    int space = 0;
    unsigned char *s = input;
    long int i = 0;
    
    /* Check characters */
    while (i < input_len) {
        switch(input[i]) {
            /* remove some characters */
            case '"':
            case '\'':
            case '\\':
            case '^':
                i++;
                continue;
                /* replace some characters to space (only one) */
            case ' ':
            case ',':
            case ';':
            case '\t':
            case '\r':
            case '\n':
                if (!space) {
                    *s++ = ' ';
                    space++;
                }
                break;
            case '/':
            case '(':
                /* remove space before / or ( */
                if (space) s--;
                space = 0;
                *s++ = input[i];
                break;
                /* copy normal characters */
            default :
                *s++ = tolower(input[i]);
                space = 0;
                
        }
        
        i++;
    }

    *s = 0;

    return s - input;
}

/* compressWhitespace */

int compressWhitespace_execute(unsigned char *input, long int input_len)
{
    long int i, j, count;

    i = j = count = 0;
    while(i < input_len) {
        if (isspace(input[i])||(input[i] == NBSP)) {
            count++;
        } else {
            if (count) {
                input[j] = ' ';
                count = 0;
                j++;
            }
            input[j] = input[i];
            j++;
        }
        i++;
    }

    if (count) {
        input[j] = ' ';
        j++;
    }
    
    return j;
}

/* hexDecode */

int hexDecode_execute(unsigned char *data, int len) {
    unsigned char *d = data;
    int i, count = 0;

    if ((data == NULL)||(len == 0)) return 0;

    for(i = 0; i <= len - 2; i += 2) {
        *d++ = x2c(&data[i]);
        count++;
    }
    *d = '\0';

    return count;
}

/* hexEncode */

/**
 * Converts a series of bytes into its hexadecimal
 * representation.
 */
int bytes2hex(char *output, unsigned char *data, int len) {
    static const unsigned char b2hex[] = "0123456789abcdef";
    int i, j;

    j = 0;
    for(i = 0; i < len; i++) {
        output[j++] = b2hex[data[i] >> 4];
        output[j++] = b2hex[data[i] & 0x0f];
    }
    output[j] = 0;

    return j;
}

/** 
 * 
 * IMP1 Assumes NUL-terminated 
 */ 
int html_entities_decode_inplace(unsigned char *input, int input_len) {
    unsigned char *d = input;
    int i, count;
    char *x;
    
    x = (char *)malloc(input_len);

    if ((x == NULL)||(input == NULL)||(input_len <= 0)) return 0;

    i = count = 0;
    while((i < input_len)&&(count < input_len)) {
        int z, copy = 1;

        /* Require an ampersand and at least one character to
         * start looking into the entity.
         */
        if ((input[i] == '&')&&(i + 1 < input_len)) {
            int k, j = i + 1;

            if (input[j] == '#') {
                /* Numerical entity. */
                copy++;

                if (!(j + 1 < input_len)) goto HTML_ENT_OUT; /* Not enough bytes. */
                j++;

                if ((input[j] == 'x')||(input[j] == 'X')) {
                    /* Hexadecimal entity. */
                    copy++;

                    if (!(j + 1 < input_len)) goto HTML_ENT_OUT; /* Not enough bytes. */
                    j++; /* j is the position of the first digit now. */

                    k = j;
                    while((j < input_len)&&(isxdigit(input[j]))) j++;
                    if (j > k) { /* Do we have at least one digit? */
                        /* Decode the entity. */
                        memcpy(x, (const char *)&input[k], j - k);
                        x[j - k] = '\0';
                        *d++ = (unsigned char)strtol(x, NULL, 16);
                        count++;

                        /* Skip over the semicolon if it's there. */
                        if ((j < input_len)&&(input[j] == ';')) i = j + 1;
                        else i = j;

                        continue;
                    } else {
                        goto HTML_ENT_OUT;
                    }
                } else {
                    /* Decimal entity. */
                    k = j;
                    while((j < input_len)&&(isdigit(input[j]))) j++;
                    if (j > k) { /* Do we have at least one digit? */
                        /* Decode the entity. */
                        memcpy(x, (const char *)&input[k], j - k);
                        x[j - k] = '\0';
                        *d++ = (unsigned char)strtol(x, NULL, 10);
                        count++;

                        /* Skip over the semicolon if it's there. */
                        if ((j < input_len)&&(input[j] == ';')) i = j + 1;
                        else i = j;

                        continue;
                    } else {
                        goto HTML_ENT_OUT;
                    }
                }
            } else {
                /* Text entity. */

                k = j;
                while((j < input_len)&&(isalnum(input[j]))) j++;
                if (j > k) { /* Do we have at least one digit? */
                    memcpy(x, (const char *)&input[k], j - k);
                    x[j - k] = '\0';

                    /* Decode the entity. */
                    /* ENH What about others? */
                    if (strcasecmp(x, "quot") == 0) *d++ = '"';
                    else
                        if (strcasecmp(x, "amp") == 0) *d++ = '&';
                        else
                            if (strcasecmp(x, "lt") == 0) *d++ = '<';
                            else
                                if (strcasecmp(x, "gt") == 0) *d++ = '>';
                                else
                                    if (strcasecmp(x, "nbsp") == 0) *d++ = NBSP;
                                    else {
                                        /* We do no want to convert this entity, copy the raw data over. */
                                        copy = j - k + 1;
                                        goto HTML_ENT_OUT;
                                    }

                    count++;

                    /* Skip over the semicolon if it's there. */
                    if ((j < input_len)&&(input[j] == ';')) i = j + 1;
                    else i = j;

                    continue;
                }
            }
        }

HTML_ENT_OUT:

        for(z = 0; ((z < copy) && (count < input_len)); z++) {
            *d++ = input[i++];
            count++;
        }
    }

    *d = '\0';
    
    free(x);

    return count;
}

/* normalizePath */

/**
 *
 * IMP1 Assumes NUL-terminated
 */
int normalize_path(unsigned char *input, int input_len, int win, unsigned char *changed) {
    unsigned char *src;
    unsigned char *dst;
    unsigned char *end;
    int ldst = 0;
    int hitroot = 0;
    int done = 0;
    int relative;
    int trailing;

    changed[0] = '0';

    /* Need at least one byte to normalize */
    if (input_len <= 0) return 0;

    /*
     * ENH: Deal with UNC and drive letters?
     */

    src = dst = input;
    end = input + (input_len - 1);
    ldst = 1;

    relative = ((*input == '/') || (win && (*input == '\\'))) ? 0 : 1;
    trailing = ((*end == '/') || (win && (*end == '\\'))) ? 1 : 0;


    while (!done && (src <= end) && (dst <= end)) {
        /* Convert backslash to forward slash on Windows only. */
        if (win) {
            if (*src == '\\') {
                *src = '/';
                changed[0] = '1';
            }
            if ((src < end) && (*(src + 1) == '\\')) {
                *(src + 1) = '/';
                changed[0] = '1';
            }
        }

        /* Always normalize at the end of the input. */
        if (src == end) {
            done = 1;
        }

        /* Skip normalization if this is NOT the end of the path segment. */
        else if (*(src + 1) != '/') {
            goto copy; /* Skip normalization. */
        }

        /*** Normalize the path segment. ***/

        /* Could it be an empty path segment? */
        if ((src != end) && *src == '/') {
            /* Ignore */
            changed[0] = '1';
            goto copy; /* Copy will take care of this. */
        }

        /* Could it be a back or self reference? */
        else if (*src == '.') {

            /* Back-reference? */
            if ((dst > input) && (*(dst - 1) == '.')) {
                /* If a relative path and either our normalization has
                 * already hit the rootdir, or this is a backref with no
                 * previous path segment, then mark that the rootdir was hit
                 * and just copy the backref as no normilization is possible.
                 */
                if (relative && (hitroot || ((dst - 2) <= input))) {
                    hitroot = 1;

                    goto copy; /* Skip normalization. */
                }

                /* Remove backreference and the previous path segment. */
                dst -= 3;
                while ((dst > input) && (*dst != '/')) {
                    dst--;
                }

                /* But do not allow going above rootdir. */
                if (dst <= input) {
                    hitroot = 1;
                    dst = input;

                    /* Need to leave the root slash if this
                     * is not a relative path and the end was reached
                     * on a backreference.
                     */
                    if (!relative && (src == end)) {
                        dst++;
                    }
                }

                if (done) goto length; /* Skip the copy. */
                src++;

                changed[0] = '1';
            }

            /* Relative Self-reference? */
            else if (dst == input) {
                changed[0] = '1';

                /* Ignore. */

                if (done) goto length; /* Skip the copy. */
                src++;
            }

            /* Self-reference? */
            else if (*(dst - 1) == '/') {
                changed[0] = '1';

                /* Ignore. */

                if (done) goto length; /* Skip the copy. */
                dst--;
                src++;
            }
        }

        /* Found a regular path segment. */
        else if (dst > input) {
            hitroot = 0;
        }

copy:
        /*** Copy the byte if required. ***/

        /* Skip to the last forward slash when multiple are used. */
        if (*src == '/') {
            unsigned char *oldsrc = src;

            while (   (src < end)
                    && ((*(src + 1) == '/') || (win && (*(src + 1) == '\\'))) )
            {
                src++;
            }
            if (oldsrc != src) changed[0] = '1';

            /* Do not copy the forward slash to the root
             * if it is not a relative path.  Instead
             * move over the slash to the next segment.
             */
            if (relative && (dst == input)) {
                src++;
                goto length; /* Skip the copy */
            }
        }

        *(dst++) = *(src++);

length:
        ldst = (dst - input);
    }

    /* Make sure that there is not a trailing slash in the
     * normalized form if there was not one in the original form.
     */
    if (!trailing && (dst > input) && *(dst - 1) == '/') {
        ldst--;
        dst--;
    }

    /* Always NUL terminate */
    *dst = '\0';

    return ldst;
}

/* removeComments */

int removeComments_execute(unsigned char *input, long int input_len, unsigned char *changed) {
    long int i, j, incomment;

    changed[0] = '0';

    i = j = incomment = 0;
    while(i < input_len) {
        if (incomment == 0) {
            if ((input[i] == '/')&&(i + 1 < input_len)&&(input[i + 1] == '*')) {
                changed[0] = '1';
                incomment = 1;
                i += 2;
            } else if ((input[i] == '<')&&(i + 1 < input_len)&&(input[i + 1] == '!')&&
                    (i + 2 < input_len)&&(input[i+2] == '-')&&(i + 3 < input_len)&&
                    (input[i + 3] == '-') && (incomment == 0)) {
                incomment = 1;
                changed[0] = '1';
                i += 4;
            } else if ((input[i] == '-')&&(i + 1 < input_len)&&(input[i + 1] == '-')
                        && (incomment == 0)) {
                changed[0] = '1';
                input[i] = ' ';
                break;
            } else if (input[i] == '#' && (incomment == 0)) {
                changed[0] = '1';
                input[i] = ' ';
               break;
            } else {
                input[j] = input[i];
                i++;
                j++;
            }
        } else {
            if ((input[i] == '*')&&(i + 1 < input_len)&&(input[i + 1] == '/')) {
                incomment = 0;
                i += 2;
                input[j] = input[i];
                i++;
                j++;
            } else if ((input[i] == '-')&&(i + 1 < input_len)&&(input[i + 1] == '-')&&
                    (i + 2 < input_len)&&(input[i+2] == '>'))   {
                incomment = 0;
                i += 3;
                input[j] = input[i];
                i++;
                j++;
            } else {
                i++;
            }
        }
    }

    if (incomment) {
        input[j++] = ' ';
    }

    return j;
}

/* removeCommentsChar */

int removeCommentsChar_execute(unsigned char *input, long int input_len, unsigned char *changed) {
    long int i, j;

    changed[0] = '0';

    i = j = 0;
    while(i < input_len) {
        if ((input[i] == '/')&&(i + 1 < input_len)&&(input[i + 1] == '*')) {
            changed[0] = '1';
            i += 2;
        } else if ((input[i] == '*')&&(i + 1 < input_len)&&(input[i + 1] == '/')) {
            changed[0] = '1';
            i += 2;
        } else if ((input[i] == '<')&&(i + 1 < input_len)&&(input[i + 1] == '!')&&
                    (i + 2 < input_len)&&(input[i+2] == '-')&&(i + 3 < input_len)&&
                    (input[i + 3] == '-')) {
            changed[0] = '1';
            i += 4;
        } else if ((input[i] == '-')&&(i + 1 < input_len)&&(input[i + 1] == '-')&&
                    (i + 2 < input_len)&&(input[i+2] == '>'))   {
            changed[0] = '1';
            i += 3;
        } else if ((input[i] == '-')&&(i + 1 < input_len)&&(input[i + 1] == '-')) {
            changed[0] = '1';
            i += 2;
        } else if (input[i] == '#') {
            changed[0] = '1';
            i++;
        } else {
            input[j] = input[i];
            i++;
            j++;
        }
    }
    input[j] = '\0';

    return j;
}

/* removeNulls */

int removeNulls_execute(unsigned char *input, long int input_len, unsigned char *changed) {
    long int i, j;

    changed[0] = '0';

    i = j = 0;
    while(i < input_len) {
        if (input[i] == '\0') {
            changed[0] = '1';
        } else {
            input[j] = input[i];
            j++;
        }
        i++;
    }

    return j;
}

/* removeWhitespace */

int removeWhitespace_execute(unsigned char *input, long int input_len, unsigned char *changed) {
    long int i, j;

    changed[0] = '0';

    i = j = 0;
    while(i < input_len) {
        if (isspace(input[i])||(input[i] == NBSP)) {
            /* do nothing */
            changed[0] = '1';
        } else {
            input[j] = input[i];
            j++;
        }
        i++;
    }

    return j;
}

/* replaceComments */

int replaceComments_execute(unsigned char *input, long int input_len, unsigned char *changed) {
    long int i, j, incomment;

    changed[0] = '0';

    i = j = incomment = 0;
    while(i < input_len) {
        if (incomment == 0) {
            if ((input[i] == '/')&&(i + 1 < input_len)&&(input[i + 1] == '*')) {
                changed[0] = '1';
                incomment = 1;
                i += 2;
            } else {
                input[j] = input[i];
                i++;
                j++;
            }
        } else {
            if ((input[i] == '*')&&(i + 1 < input_len)&&(input[i + 1] == '/')) {
                incomment = 0;
                i += 2;
                input[j] = ' ';
                j++;
            } else {
                i++;
            }
        }
    }

    if (incomment) {
        input[j++] = ' ';
    }

    return j;
}

/* replaceNulls */

int replaceNulls_execute(unsigned char *input, long int input_len) {
    long int i;
    int changed = 0;

    i = 0;
    while(i < input_len) {
        if (input[i] == '\0') {
            changed = 1;
            input[i] = ' ';
        }
        i++;
    }

    return changed;
}

/* trimLeft */

int trimLeft_execute(unsigned char *input, long int input_len) {
    long int i;

    for(i = 0; i < input_len; i++) {
        if (isspace(input[i]) == 0) {
            break;
        }
    }

    return i;
}

/* trimRight */

int trimRight_execute(unsigned char *input, long int input_len) {
    long int i = input_len - 1;

    while(i >= 0) {
        if (isspace(input[i]) == 0) {
            break;
        }
        input[i] = '\0';
        i--;
    }

    return i + 1;
}

/* trim */

int trim_execute(unsigned char *input, long int input_len) {
    int len = input_len;

    len = trimRight_execute(input, len);
    len = trimLeft_execute(input, len);

    return len;
}

/* sqlHexDecode */

/**
 *
 */
int sql_hex2bytes(unsigned char *data, int len) {
    unsigned char *d, *begin = data;

    if ((data == NULL)||(len == 0)) return 0;

    for( d = data; *data; *d++ = *data++) {
        if ( *data != '0' ) continue;
        if ( tolower(*++data) != 'x' ) {
            data--;
            continue;
        }

        data++;

        // Do we need to keep "0x" if no hexa after?
        if ( !VALID_HEX(data[0]) || !VALID_HEX(data[1]) ) {
            data-=2;
            continue;
        }

        while ( VALID_HEX(data[0]) && VALID_HEX(data[1]) )  {
            *d++ = x2c(data);
            data += 2;
        }
    }

    *d = '\0';
    return strlen((char *)begin);
}