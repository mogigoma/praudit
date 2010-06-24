#include <bsm/libbsm.h>

#include <stdlib.h>

#include "tokenify.h"

extern char	*del;
extern int	 oneline;
extern int	 raw;
extern int	 shortfrm;
extern int	 partial;
extern int	 xml;

int
print_text_tokens(FILE *fp)
{
	u_char *buf;
	tokenstr_t tok;
	int reclen;
	int bytesread;

	/* Allow tail -f | praudit to work. */
	if (partial) {
		u_char type = 0;
		/* Record must begin with a header token. */
		do {
			type = fgetc(fp);
		} while(type != AUT_HEADER32);
		ungetc(type, fp);
	}

	while ((reclen = au_read_rec(fp, &buf)) != -1) {
		bytesread = 0;
		while (bytesread < reclen) {
			/* Is this an incomplete record? */
			if (-1 == au_fetch_tok(&tok, buf + bytesread,
			    reclen - bytesread))
				break;
			if (xml)
				au_print_tok_xml(stdout, &tok, del, raw,
				    shortfrm);
			else
				au_print_tok(stdout, &tok, del, raw,
				    shortfrm);
			bytesread += tok.len;
			if (oneline) {
				if (!xml)
					printf("%s", del);
			} else
				printf("\n");
		}
		free(buf);
		if (oneline)
			printf("\n");
		fflush(stdout);
	}

	return (0);
}
