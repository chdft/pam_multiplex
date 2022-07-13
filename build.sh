#! /bin/bash
if [[ "$1" = "DEBUG" ]]; then
	#HACK: use O3 even for debug builds since gcc produces much better diagnostics with O3 than with O0…
	#TODO: consider changing to CLANG
	FLAGS="-DDEBUG -O3"
else
	FLAGS="-O3"
fi
CVERSION="gnu11"
# test app
gcc pam_multiplex.c -lpam -lpam_misc -std=$CVERSION $FLAGS
# pam module
gcc -fPIC -fno-stack-protector $FLAGS -std=$CVERSION -c pam_multiplex.c
ld -x --shared -o pam_multiplex.so pam_multiplex.o
