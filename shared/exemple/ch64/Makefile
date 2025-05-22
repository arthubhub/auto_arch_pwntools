CROSS_COMPILE   = mips-linux-gnu-
CC              = gcc
NAMEMAIN        = ch64

LD              = gcc
RM              = rm -f

MAINSOURCE	= $(NAMEMAIN).c

MAINOBJ		= $(MAINSOURCE:.c=.o)

MAINLDFLAGS	= -Werror -Wall -W -ansi -pedantic --std=c99 -no-pie -fno-stack-protector -Wl,-z,relro,-z,now -z noexecstack
MAINCFLAGS	= -c -Werror -Wall -W -ansi -pedantic -fno-stack-protector --std=c99

all: $(NAMEMAIN) post-build

$(NAMEMAIN): $(MAINOBJ)
	$(CROSS_COMPILE)$(CC) -o $@ $(MAINOBJ) $(MAINLDFLAGS)

$(MAINOBJ): $(MAINSOURCE)
	$(CROSS_COMPILE)$(CC) -o $@ -c $< $(MAINCFLAGS)

fclean: clean
	$(RM)   $(NAMEMAIN)

clean:
	$(RM)		$(MAINOBJ)

post-build:
	chown -R app-systeme-$(NAMEMAIN)-cracked:app-systeme-$(NAMEMAIN) $(MAINSOURCE) $(NAMEMAIN) .passwd Makefile
	chmod -R o= .
	chmod 400 .passwd $(MAINSOURCE)
	$(MAKE) clean

re: fclean all

.PHONY: all clean fclean re
