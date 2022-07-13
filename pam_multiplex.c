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
#include <stdbool.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

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

#define array_size(array) ((sizeof(array))/(sizeof(array[0])))

typedef struct{
	char *stackName;
	int *lateRetVal;
	int parentFlags;
	pam_handle_t *parentPamh;
	bool* cancelationToken;
	bool allowPrompts; 
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
	for(int i = 0; i < array_size(itemTypes); i++){
		int itemType = itemTypes[i];
		const void* item;
		int retval = pam_get_item(sourcePamh, itemType, &item);
		if(retval == PAM_SUCCESS){
			pam_set_item(destinationPamh, itemType, item);
		}
	}
}

/*struct pam_conv {
    int (*conv)(int num_msg, const struct pam_message **msg,
                struct pam_response **resp, void *appdata_ptr);
    void *appdata_ptr;
};*/
typedef struct{
	const struct pam_conv *conv;
	bool* cancelationToken;
	bool allowPrompts;
} conv_proxy_data;
int proxy_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr){
	debug_print("proxy_conv\n", 0);
	conv_proxy_data* proxy_data = appdata_ptr;
	if(*(proxy_data->cancelationToken)){
		debug_print("proxy_conv canceled\n", 0);
		return PAM_CONV_ERR;
	}else{
		debug_print("proxy_conv not canceled\n", 0);
		if(!proxy_data->allowPrompts){
			debug_print("proxy_conv prompts not allowed\n", 0);
			for(int i = 0; i < num_msg; i++){
				//this uses linux style "array of pointers"-msg (there is also the "pointer to array"-msg)
				//  see also https://web.archive.org/web/20190513193446/http://www.linux-pam.org/Linux-PAM-html/adg-interface-of-app-expected.html#adg-pam_conv
				if(msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON){
					debug_print("proxy_conv non-forward due to prompt filter in msg %i\n", i);
					return PAM_CONV_ERR;
				}
			}
		}
		
		debug_print("proxy_conv forwarding…\n", 0);
		return proxy_data->conv->conv(num_msg, msg, resp, proxy_data->conv->appdata_ptr);
	}
}

void* stack_host_main(void* arg){
	stack_host_args* typedArg = (stack_host_args*)arg;
	debug_print("multiplex \"%s\": starting background thread with config %p for %p\n", typedArg->stackName, typedArg, typedArg->parentPamh);
	//debug_msleep(2000L);
	//*(typedArg->lateRetVal) = PAM_SUCCESS;
	//return NULL;
	
	// https://github.com/beatgammit/simple-pam provides a pretty minimal example of a PAM module/application and was used as inspiration
	
	pam_handle_t* pamh = NULL;
	int retval;
	const char* user = NULL;

	//wrap conversation function
	//  proxy conv and drop messages after the main thread reported success on another thread to avoid cluttering the console
	const struct pam_conv *parentConv = &pam_default_conv;
	const void* parentConvV;
	pam_get_item(typedArg->parentPamh, PAM_CONV, &parentConvV);
	parentConv = parentConvV;
	
	conv_proxy_data proxy_data = {
		.conv=parentConv,
		.cancelationToken=typedArg->cancelationToken,
		.allowPrompts=typedArg->allowPrompts
	};
	const struct pam_conv conv = {
		.conv=proxy_conv,
		.appdata_ptr=&proxy_data
	};

	retval = pam_start(typedArg->stackName, user, &conv, &pamh);
	const void* retrievedConv;
	pam_get_item(pamh, PAM_CONV, &retrievedConv);
	debug_print("multiplex \"%s\": conv retrieved=%p, set=%p, parent=%p, default=%p\n", typedArg->stackName, retrievedConv, &conv, parentConv, &pam_default_conv);
	pam_set_item(pamh, PAM_CONV, &conv); //somehow the custom conv is ignored without setting it twice
	pam_get_item(pamh, PAM_CONV, &retrievedConv);
	debug_print("multiplex \"%s\": conv retrieved=%p, set=%p, parent=%p, default=%p\n", typedArg->stackName, retrievedConv, &conv, parentConv, &pam_default_conv);
	pam_set_item(pamh, PAM_CONV, &conv); //somehow the custom conv is ignored without setting it twice
	pam_get_item(pamh, PAM_CONV, &retrievedConv);
	debug_print("multiplex \"%s\": conv retrieved=%p, set=%p, parent=%p, default=%p\n", typedArg->stackName, retrievedConv, &conv, parentConv, &pam_default_conv);
	pam_set_item(pamh, PAM_CONV, &conv); //somehow the custom conv is ignored without setting it twice
	pam_get_item(pamh, PAM_CONV, &retrievedConv);
	debug_print("multiplex \"%s\": conv retrieved=%p, set=%p, parent=%p, default=%p\n", typedArg->stackName, retrievedConv, &conv, parentConv, &pam_default_conv);
	pam_set_item(pamh, PAM_CONV, &conv); //somehow the custom conv is ignored without setting it twice
	pam_get_item(pamh, PAM_CONV, &retrievedConv);
	debug_print("multiplex \"%s\": conv retrieved=%p, set=%p, parent=%p, default=%p\n", typedArg->stackName, retrievedConv, &conv, parentConv, &pam_default_conv);
	pam_set_item(pamh, PAM_CONV, &conv); //somehow the custom conv is ignored without setting it twice
	pam_get_item(pamh, PAM_CONV, &retrievedConv);
	debug_print("multiplex \"%s\": conv retrieved=%p, set=%p, parent=%p, default=%p\n", typedArg->stackName, retrievedConv, &conv, parentConv, &pam_default_conv);

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
	debug_print("pam_multiplex pam_sm_authenticate start for pamh=%p\n", pamh);
	if(argc < 2){
		//insufficient parameters
		return PAM_AUTHINFO_UNAVAIL;
	}
	debug_msleep(1000L); //use exponential sleep to enable side-channel based debugging
	debug_print("pam_multiplex pam_sm_authenticate state init\n", 0);
	long iterationDurationMs = 100L;
	int timeoutDurationS = atoi(argv[0]); //note that argv[0] is *not* the module name
	int timeoutIterations = timeoutDurationS * 1000L / iterationDurationMs;
	int subStackCount = argc-1;
	stack_host_args params[subStackCount];
	pthread_t thread_infos[subStackCount];
	int results[subStackCount];
	bool cancelationToken = false;
	debug_print("pam_multiplex pam_sm_authenticate start background threads\n", 0);
	debug_msleep(2000L);
	//start substacks
	for(int subStackIndex = 0; subStackIndex < subStackCount; subStackIndex++){
		debug_print("pam_multiplex preparing substack %i=\"%s\" for %p\n", subStackIndex, argv[subStackIndex+1], pamh);
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
		//+1 the argv index to ignore timeout
		//+1 the string to skip first character
		params[subStackIndex].stackName = (*(char**)&(argv[subStackIndex+1]))+1;
		params[subStackIndex].lateRetVal = &results[subStackIndex];
		params[subStackIndex].parentFlags = flags;
		params[subStackIndex].parentPamh = pamh;
		params[subStackIndex].cancelationToken = &cancelationToken;
		//TODO consider only allowing prompts on substack 0
		switch(argv[subStackIndex+1][0]){
			case '+': params[subStackIndex].allowPrompts = true; break;
			case '-': params[subStackIndex].allowPrompts = false; break;
			default: 
				debug_print("pam_multiplex pam_sm_authenticate multiplex \"%s\" does not have a supported prefix \n", params[subStackIndex].stackName);
				return PAM_AUTHINFO_UNAVAIL;
		}
		
		pthread_create(&thread_infos[subStackIndex], NULL, stack_host_main, &params[subStackIndex]);
	}
	debug_msleep(4000L);
	//for the proof of concept we use polling (easier to do correctly)
	//TODO reimplement using proper locking instead of polling
	for(int iteration = 0; iteration <= timeoutIterations; iteration++){
		debug_print("5::%i::%i\n", iteration, timeoutIterations);
		for(int subStackIndex = 0; subStackIndex < subStackCount; subStackIndex++){
			if(results[subStackIndex] != MULTIPLEX_NOT_READY){
				debug_print("value available from substack %i\n", subStackIndex);
				cancelationToken = true; //cancel other stacks
				return results[subStackIndex];
			}
		}
		
		//sleep for 100ms=0.1s
		msleep(iterationDurationMs);
	}
	//only reached after timeout triggered
	cancelationToken = true; //cancel all stacks
	return PAM_AUTHINFO_UNAVAIL;
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
