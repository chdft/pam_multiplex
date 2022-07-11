/*
 * Copyright (c) 2005, 2006 Thorsten Kukuk <kukuk@suse.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

//#include "pam_inline.h"

#define MULTIPLEX_NOT_READY -1337

#ifdef DEBUG
	#define debug_print(fmt, ...) \
				do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)
	#define debug_msleep(time) \
				do { msleep(time); } while (0)
#else
	#define debug_print(fmt, ...) do { } while (0)
	#define debug_msleep(time) do { } while (0)
#endif

typedef struct{
	char *stackName;
	int *lateRetVal;
	int parentFlags;
	pam_handle_t *parentPamh;
} stack_host_args;

const struct pam_conv pam_default_conv = {
	misc_conv,
	NULL
};

/* msleep(): Sleep for the requested number of milliseconds. */
void msleep(long msec)
{
	struct timespec ts;

	if (msec < 0)
	{
		return;
	}

	ts.tv_sec = msec / 1000;
	ts.tv_nsec = (msec % 1000) * 1000000;
	
	//we intentionally ignore interrupts, since this is called from a loop anyways
	nanosleep(&ts, &ts);
}

char* pam_code_to_str(int pam_result){
	switch(pam_result){
		case PAM_SUCCESS: return "SUCCESS";
		//application side
		//pam_authenticate
		case PAM_ABORT: return "PAM_ABORT";
		case PAM_AUTH_ERR: return "PAM_AUTH_ERR";
		case PAM_CRED_INSUFFICIENT: return "PAM_CRED_INSUFFICIENT";
		case PAM_AUTHINFO_UNAVAIL: return "PAM_AUTHINFO_UNAVAIL";
		case PAM_MAXTRIES: return "PAM_MAXTRIES";
		case PAM_USER_UNKNOWN: return "PAM_USER_UNKNOWN";
		//pam_start
		case PAM_BUF_ERR: return "PAM_BUF_ERR";
		case PAM_SYSTEM_ERR: return "PAM_SYSTEM_ERR";
		//set item
		case PAM_BAD_ITEM: return "PAM_BAD_ITEM";
		
		//module side
		case PAM_CRED_UNAVAIL: return "PAM_CRED_UNAVAIL";
		case PAM_CRED_EXPIRED: return "PAM_CRED_EXPIRED";
		case PAM_CRED_ERR: return "PAM_CRED_ERR";
		default: return "?";
	}
}

void copy_pam_items(pam_handle_t *sourcePamh, pam_handle_t *destinationPamh){
	int itemTypes[] = {
		PAM_USER,
		PAM_USER_PROMPT,
		PAM_TTY,
		PAM_RUSER,
		PAM_RHOST,
		PAM_AUTHTOK,
		PAM_OLDAUTHTOK,
		PAM_CONV,
		PAM_FAIL_DELAY,
		PAM_XDISPLAY,
		PAM_XAUTHDATA,
		PAM_AUTHTOK_TYPE
	};
	for(int i = 0; i < sizeof(itemTypes); i++){
		int itemType = itemTypes[i];
		const void* item;
		int retval = pam_get_item(sourcePamh, itemType, &item);
		if(retval == PAM_SUCCESS){
			pam_set_item(destinationPamh, itemType, item);
		}
	}
}

void* stack_host_main(void* arg){
	stack_host_args* typedArg = (stack_host_args*)arg;
	debug_print("multiplex \"%s\": starting background thread\n", typedArg->stackName);
	//debug_msleep(2000L);
	//*(typedArg->lateRetVal) = PAM_SUCCESS;
	//return NULL;
	
	// https://github.com/beatgammit/simple-pam provides a pretty minimal example of a PAM module/application and was used as inspiration
	
	pam_handle_t* pamh = NULL;
	int retval;
	const char* user = NULL;

	//copy conversation function
	const struct pam_conv *conv = &pam_default_conv;
	const void* item;
	pam_get_item(typedArg->parentPamh, PAM_CONV, &item);
	conv = item;

	retval = pam_start(typedArg->stackName, user, conv, &pamh);

	// Are the credentials correct?
	if (retval != PAM_SUCCESS) {
		debug_print("multiplex \"%s\": starting stack failed\n", typedArg->stackName);
		return NULL;
	}

	debug_print("multiplex \"%s\": session opened\n", typedArg->stackName);
	copy_pam_items(typedArg->parentPamh, pamh);
	debug_print("multiplex \"%s\": items copied\n", typedArg->stackName);
	
	retval = pam_authenticate(pamh, typedArg->parentFlags);

	/*// Can the accound be used at this time?
	if (retval == PAM_SUCCESS) {
		debug_print("Account is valid.\n");
		retval = pam_acct_mgmt(pamh, 0);
	}*/

	// Did everything work?
	*(typedArg->lateRetVal) = retval;
	debug_print("multiplex \"%s\": Auth=%i=%s\n", typedArg->stackName, retval, pam_code_to_str(retval));

	// close PAM (end session)
	if (pam_end(pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		debug_print("multiplex \"%s\": failed to release PAM application side handle; retval=%i\n", typedArg->stackName, retval);
	}
	debug_print("multiplex \"%s\": ending background thread\n", typedArg->stackName);
	return NULL;
}


int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	//args: timeoutInSeconds module1 [module2 […]]
	if(argc < 2){
		//insufficient parameters
		return PAM_AUTH_ERR;
	}
	debug_print("%i\n", 1);
	debug_msleep(1000L); //use exponential sleep to enable side-channel based debugging
	debug_print("%i\n", 2);
	long iterationDurationMs = 100L;
	int timeoutDurationS = atoi(argv[0]);
	int timeoutIterations = timeoutDurationS * 1000L / iterationDurationMs;
	int subStackCount = argc-1;
	debug_msleep(2000L);
	stack_host_args params[subStackCount];
	pthread_t thread_infos[subStackCount];
	int results[subStackCount];
	debug_print("%i\n", 3);
	debug_msleep(4000L);
	//start substacks
	for(int subStackIndex = 0; subStackIndex < subStackCount; subStackIndex++){
		debug_print("4;%i\n", subStackIndex);
		results[subStackIndex] = MULTIPLEX_NOT_READY;
		/*params[subStackIndex] = (stack_host_args) {
			.stackName = argv[subStackIndex],
			.lateRetVal = &results[subStackIndex],
			.parentFlags = flags,
			.parentPamh = pamh
		};
		params[subStackIndex] = {
			argv[subStackIndex],
			&results[subStackIndex],
			flags,
			pamh
		};*/
		params[subStackIndex].stackName = (*(char**)&(argv[subStackIndex+1])) ;
		params[subStackIndex].lateRetVal = &results[subStackIndex];
		params[subStackIndex].parentFlags = flags;
		params[subStackIndex].parentPamh = pamh;
		pthread_create(&thread_infos[subStackIndex], NULL, stack_host_main, &params[subStackIndex]);
	}
	debug_msleep(8000L);
	//for the proof of concept we use polling (easier to do correctly)
	//TODO reimplement using proper locking instead of polling
	for(int iteration = 0; iteration <= timeoutIterations; iteration++){
		debug_print("5::%i::%i\n", iteration, timeoutIterations);
		for(int subStackIndex = 0; subStackIndex < subStackCount; subStackIndex++){
			if(results[subStackIndex] != MULTIPLEX_NOT_READY){
				debug_print("value available from substack %i\n", subStackIndex);
				return results[subStackIndex];
			}
		}
		
		//sleep for 100ms=0.1s
		msleep(iterationDurationMs);
	}
	//should be unreachable
	return PAM_AUTH_ERR;
}

int
pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_IGNORE;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_IGNORE;
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_IGNORE;
}

int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_IGNORE;
}

int
pam_sm_chauthtok (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_IGNORE;
}

//main method for standalone mode (only used for testing)
int main(int argc, const char** argv){
	debug_print("main-start\n", 0);
	int result = pam_sm_authenticate(NULL, 0, argc-1, argv+1);
	debug_print("result: %i=%s\n", result, pam_code_to_str(result));
	debug_print("main-end\n", 0);
	return 0;
}
