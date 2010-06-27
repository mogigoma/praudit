CC=gcc
CFLAGS=-Wall -g
LIBS=-l bsdxml -l bsm
OBJS=attributes.o	\
     elements.o		\
     praudit.o		\
     token_buffer.o	\
     tokenify_binary.o	\
     tokenify_text.o

all: praudit

praudit: $(OBJS)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

.c.o:
	@echo "[CC] $@"
	@$(CC) $(CFLAGS) -c $<

clean:
	@rm -f praudit
	@rm -f $(OBJS)
	@rm -f *.core
