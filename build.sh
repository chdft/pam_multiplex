#! /bin/bash
if [[ "$1" = "DEBUG" ]]; then
	FLAGS="-DDEBUG"
fi
# test app
gcc pam_multiplex.c -lpam -lpam_misc $FLAGS
# pam module
gcc -fPIC -fno-stack-protector $FLAGS -c pam_multiplex.c
ld -x --shared $FLAGS -o pam_multiplex.so pam_multiplex.o
