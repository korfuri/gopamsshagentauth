package main

// #cgo LDFLAGS: -lpam
// #include <security/pam_modules.h>
// #include <security/pam_appl.h>
import "C"

import (
	"fmt"
	"unsafe"
)

type PamHandle struct {
	p unsafe.Pointer
}

func (p PamHandle) ptr() *C.pam_handle_t {
	return (*C.pam_handle_t)(p.p);
}

func getHandle(h *C.pam_handle_t) PamHandle {
	return PamHandle{unsafe.Pointer(h)}
}

//export authenticate
func authenticate(handle *C.pam_handle_t, flags C.int, argv []string) C.int {
	fmt.Printf("authenticate: %v", argv)
	return C.PAM_SUCCESS
}

//export openSession
func openSession(handle *C.pam_handle_t, flags C.int, argv []string) C.int {
	// h := pam.Handle(unsafe.Pointer(handle))
	fmt.Printf("open_session: %v", argv)
	return C.PAM_SUCCESS
}

//export closeSession
func closeSession(handle *C.pam_handle_t, flags C.int, argv []string) C.int {
	fmt.Printf("close_session: %v", argv)
	return C.PAM_SUCCESS
}

func main() {
	panic("this is a shared library, not an executable binary")
}
