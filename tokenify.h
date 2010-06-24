#ifndef TOKENIFY_H_
#define TOKENIFY_H_

#include <stdio.h>

#define TXT_BUFFER_SIZE	1024
#define XML_BUFFER_SIZE	1024

int	print_binary_tokens(FILE *fp);
int	print_text_tokens(FILE *fp);

#endif
