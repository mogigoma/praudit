#include <assert.h>
#include <bsdxml.h>
#include <ctype.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elements.h"
#include "tokenify.h"

static char	*txt_buf;
static char	*txt_buf_clean;
static int	 txt_buf_left;
static int	 txt_buf_size;

static void
startElement(void *data, const char *el, const char **attr)
{

	/* Call element handler. */
	handleElement(el, attr, NULL);
}

static void
insideElement(void *data, const XML_Char *xml, int len)
{

	/* Grow buffer. */
	if (txt_buf_left < len) {
		while (txt_buf_left < len) {
			txt_buf_left += (txt_buf_size << 1) - txt_buf_size;
			txt_buf_size <<= 1; /* XXX-MAK: Add overflow check. */
		}

		txt_buf = realloc(txt_buf, txt_buf_size);
		if (txt_buf == NULL)
			err(1, "[realloc]");
	}

	/* Append to buffer. */
	strncat(txt_buf, xml, len);
	txt_buf_left -= len;
}

static void
endElement(void *data, const char *el)
{
	int i;

	/* Remove trailing whitespace. */
	i = txt_buf_size - txt_buf_left;
	while (isspace(txt_buf[i]) && i >= 0)
		i--;
	txt_buf[i] = '\0';

	/* Remove leading whitespace. */
	txt_buf_clean = txt_buf;
	while (isspace(*txt_buf_clean))
		txt_buf_clean++;

	/* Call element handler. */
	handleElement(el, NULL, txt_buf_clean);

	/* Reset text buffer. */
	bzero(txt_buf, txt_buf_size);
	txt_buf_left = txt_buf_size - 1;
}

int
print_binary_tokens(FILE *fp)
{
	int bytes_read, fd;
	XML_Parser parser;
	void *xml_buf;

	/* Convert file pointer to file descriptor. */
	fd = fileno(fp);

	/* Initialize text buffer. */
	txt_buf_size = TXT_BUFFER_SIZE;
	txt_buf_left = txt_buf_size - 1;
	txt_buf = calloc(txt_buf_size, sizeof(char));
	if (txt_buf == NULL)
		err(1, "[calloc]");

	/* Initialize parser. */
	parser = XML_ParserCreate(NULL);
	XML_SetCharacterDataHandler(parser, insideElement);
	XML_SetElementHandler(parser, startElement, endElement);

	/* Feed data to parser. */
	for (;;) {
		xml_buf = XML_GetBuffer(parser, XML_BUFFER_SIZE);
		if (xml_buf == NULL) {
			warn("[XML_GetBuffer]");
			break;
		}

		bytes_read = read(fd, xml_buf, XML_BUFFER_SIZE);
		if (bytes_read == -1) {
			warn("[read]");
			break;
		}

		if (XML_ParseBuffer(parser, bytes_read, bytes_read == 0) == -1) {
			warn("[XML_ParseBuffer]");
			break;
		}

		if (bytes_read == 0)
			break;
	}

	/* Clean up. */
	XML_ParserFree(parser);
	free(txt_buf);

	return (0);
}
