#include "string.h"
#include "stdlib.h"

#include "_cgo_export.h"

#define PAM_SM_AUTH
//#define PAM_SM_PASSWORD
//#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <sys/types.h>
#include <pwd.h>

GoSlice argcvToSlice(int argc, const char** argv) {
  GoString* strs = malloc(sizeof(GoString) * argc);

  GoSlice ret;
  ret.cap = argc;
  ret.len = argc;
  ret.data = (void*)strs;

  for(int i = 0; i < argc; i++) {
    strs[i].p = (char*)argv[i];
    strs[i].n = strlen(argv[i]);
  }

  return ret;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv){
  const char* username;
  int r = pam_get_item(handle, PAM_RUSER, (const void**)&username);
  if (r != PAM_SUCCESS) {
	c_log("failed pam_get_item");
	return r;
  }
  if (username == NULL) {
	c_log("username is null");
	return PAM_USER_UNKNOWN;
  }

  // We probably shouldnt getpwnam here, we should be asking PAM for
  // the uid & gid of the target user rather than the username
  struct passwd* pw = getpwnam(username);
  free((void*)username);
  if (pw == NULL) {
	c_log("failed getpwnam");
	return PAM_USER_UNKNOWN;
  }

  return authenticate(handle, pw->pw_uid, pw->pw_gid, argcvToSlice(argc, argv));
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_IGNORE;
}
