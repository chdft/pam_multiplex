#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>


const struct pam_conv conv = {
	misc_conv,
	NULL
};

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

int main(int argc, char *argv[]) {
	pam_handle_t* pamh = NULL;
	int retval;

	if(argc != 3) {
		printf("Usage: ./app username stackname\n");
		exit(1);
	}

	const char* user = argv[1];
	const char* stackName = argv[2];

	printf("starting PAM\n");
	retval = pam_start(stackName, user, &conv, &pamh);

	// Are the credentials correct?
	if (retval == PAM_SUCCESS) {
		printf("starting authenticate…\n");
		retval = pam_authenticate(pamh, 0);
		printf("pam_authenticate() -> %i=%s\n", retval, pam_code_to_str(retval));
	}else{
		printf("starting PAM failed: %i=%s\n", retval, pam_code_to_str(retval));
	}

	// close PAM (end session)
	if (pam_end(pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		printf("check_user: failed to release authenticator\n");
		exit(1);
	}

	return retval == PAM_SUCCESS ? 0 : 1;
}
