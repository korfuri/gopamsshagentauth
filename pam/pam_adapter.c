#include "string.h"
#include "stdlib.h"

#include "_cgo_export.h"

#define PAM_SM_AUTH
//#define PAM_SM_PASSWORD
//#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_appl.h>

GoSlice argcvToSlice(int argc, const char** argv) {
  GoString* strs = malloc(sizeof(GoString) * argc);

  GoSlice ret;
  ret.cap = argc;
  ret.len = argc;
  ret.data = (void*)strs;

  int i;
  for(i = 0; i < argc; i++) {
    strs[i] = *((GoString*)malloc(sizeof(GoString)));

    strs[i].p = (char*)argv[i];
    strs[i].n = strlen(argv[i]);
  }

  return ret;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv){
  // In this function we will ask the username and the password with
  // pam_get_user() and pam_get_authtok(). We will then decide if the
  // user is authenticated
  return authenticate(handle, flags, argcvToSlice(argc, argv));
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  // We could have many more information of the user other then
  // password and username. These are the credentials. For example, a
  // kerberos ticket. Here we establish those and make them visible to
  // the application
}
