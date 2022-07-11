#! /bin/bash
if [[ "$1" = "DEBUG" ]]; then
	FLAGS="-DDEBUG"
fi
CVERSION="gnu11"
# test app
gcc pam_multiplex.c -lpam -lpam_misc -std=$CVERSION $FLAGS
# pam module
gcc -fPIC -fno-stack-protector $FLAGS -std=$CVERSION -c pam_multiplex.c
ld -x --shared -o pam_multiplex.so pam_multiplex.o
