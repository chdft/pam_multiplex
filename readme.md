# PAM Multiplexer

PAM Multiplexer is a PAM module that internally calls N (N>=1) other stacks in the background and returns the result of the first sub-stack that provides one. This provides a way to run multiple modules in parallel.

## Usage
In your primary PAM stack (S0) - for example `/etc/pamd.d/login` - add a line for the multiplexer module. This line will probably look like this:
```
auth	required	pam_multiplexer.so 30 -my-otp-stack -my-fingerprint-stack +my-pin-stack
```
Where `30` is the timeout in seconds, and `my-otp-stack`, `my-fingerprint-stack`, `my-pin-stack` are the different sub-stacks (S1-S3) that are invoked. The stacks with a `+` prefix (usually just 1) are allowed to prompt for input, while stacks with the `-` prefix get a conversation-error when attempting to prompt (but console *output* is always allowed).

PAM Multiplexer takes care to provide the same standard PAM items that are also present in S0 to Sn, but module data is not copied.
The substacks Sn need to be standard PAM stacks and can make use of all PAM features (including another Multiplexer module instance).
It is recommended that only 1 of the N substacks takes conv-function based interactive input (=> do not use 2 different password providers since they will likely clash and produce wierd console output, but using password+fingerprint is fine, because the fingerprint module does not *read* from the console).

Since only a single substack will be followed to completion, care needs to be taken to make sure that:
- all modules in Sn terminate on their own after a timeout (or immediately)
- the Sn either do not contain invocations of fail-counters or correctly differentiate between the no-interaction-timeout and incorrect-input cases in order to avoid locking out a user / logging bogus fails because the user authenticated using a different stack
- the Sn do no hold resources that might be needed immediately after the successful authentication (for example during a password change) and do not provide a good method for concurrent access. This notable includes the console itself.

## Testing (for Admins)
You can use the tool in the `/tester` directory to test a stack using this command line:
```
./tester username stackname
```
You would generally use your own username (or a dedicated test account) for username and the name of S0 for stackname.

## Design Decisions and TODO

- the availability of a result in the substacks is polled at 10Hz; this was done for ease of development to get to a working MVP more quickly
- required timeout for the module: While I have not come across any problems *yet*, many (old) forum threads and not so old GitHub issues state that PAM is conceptually incompatible with multi-threading. This module makes use of multi-threading. To avoid unanticipated deadlocks during authentication, there is a required (but user chosen) timeout, after which `PAM_AUTH_ERR` is returned.
- only `auth` is supported: multiplexing does not really make sense for the other methods (`account` and `session` should use all modules sequentially since no user interaction is anticipated, `password` would provide an odd UX when only 1 of N passwords is actually changed)
- The `conv` function is passed to all substacks despite only a single being supposed to actually use it: All PAM stacks need *some* `conv` function. Providing S0s `conv` was easiest for now, but better solutions are welcome.
- sub-stacks instead of sub-modules: 
	- PAM only provides a documented API to start an entire stack, but not a single module => this way is more stable
	- each parallel sub-module needs to run on a separate PAM handle, since thread safety of the module-facing APIs is not documented, but likely not provided
	- sub-modules still need separate arg-lists; This would result in a complex syntax for invoking the multiplex module.

## Building
To build with DEBUG-output (including side-channel debug delays), include the `DEBUG` parameter when invoking `build.sh`.
```
./build.sh #compile and link
sudo ./install.sh #install module file into system-wide directory (does not modify stacks)
./tester/build.sh #build tester tool
```
