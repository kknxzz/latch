//go:build darwin && cgo

package identity

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static CFMutableDictionaryRef latch_query(const char *account) {
 CFMutableDictionaryRef q=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 if (!q) return NULL;
 CFStringRef a=CFStringCreateWithCString(NULL,account,kCFStringEncodingUTF8);
 if (!a) {CFRelease(q);return NULL;}
 CFDictionarySetValue(q,kSecClass,kSecClassGenericPassword);
 CFDictionarySetValue(q,kSecAttrService,CFSTR("Latch Device Identity"));
 CFDictionarySetValue(q,kSecAttrAccount,a);CFRelease(a);return q;
}
static OSStatus latch_load(const char *account,unsigned char **out,size_t *len) {
 *out=NULL;*len=0;CFMutableDictionaryRef q=latch_query(account);if(!q)return errSecAllocate;
 CFDictionarySetValue(q,kSecReturnData,kCFBooleanTrue);
 CFDictionarySetValue(q,kSecMatchLimit,kSecMatchLimitOne);
 CFTypeRef value=NULL;OSStatus status=SecItemCopyMatching(q,&value);CFRelease(q);
 if(status!=errSecSuccess)return status;
 if(!value||CFGetTypeID(value)!=CFDataGetTypeID()){if(value)CFRelease(value);return errSecDecode;}
 CFIndex n=CFDataGetLength((CFDataRef)value);if(n<1||n>8192){CFRelease(value);return errSecDecode;}
 unsigned char *bytes=malloc((size_t)n);if(!bytes){CFRelease(value);return errSecAllocate;}
 memcpy(bytes,CFDataGetBytePtr((CFDataRef)value),(size_t)n);CFRelease(value);*out=bytes;*len=(size_t)n;return errSecSuccess;
}
static OSStatus latch_save(const char *account,const unsigned char *bytes,size_t len) {
 CFMutableDictionaryRef q=latch_query(account);if(!q)return errSecAllocate;
 CFDataRef data=CFDataCreate(NULL,bytes,(CFIndex)len);if(!data){CFRelease(q);return errSecAllocate;}
 CFDictionarySetValue(q,kSecValueData,data);
 CFDictionarySetValue(q,kSecAttrAccessible,kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
 OSStatus status=SecItemAdd(q,NULL);CFRelease(data);CFRelease(q);return status;
}
static void latch_free_secret(unsigned char *data,size_t len){if(data){memset_s(data,len,0,len);free(data);}}
*/
import "C"

import (
	"errors"
	"os"
	"runtime"
	"unsafe"
)

var ErrKeychain = errors.New("Keychain unavailable, locked, or permission denied")

type KeychainBackend struct{}

func (KeychainBackend) Load(account string) ([]byte, error) {
	if !ValidUUID(account) {
		return nil, ErrInvalid
	}
	a := C.CString(account)
	defer C.free(unsafe.Pointer(a))
	var data *C.uchar
	var length C.size_t
	status := C.latch_load(a, &data, &length)
	if status == C.errSecItemNotFound {
		return nil, os.ErrNotExist
	}
	if status != C.errSecSuccess {
		return nil, ErrKeychain
	}
	defer C.latch_free_secret(data, length)
	return C.GoBytes(unsafe.Pointer(data), C.int(length)), nil
}

// Save creates a new item only. A conflicting account is never silently replaced.
func (KeychainBackend) Save(account string, data []byte) error {
	if !ValidUUID(account) || len(data) == 0 || len(data) > 8192 {
		return ErrInvalid
	}
	a := C.CString(account)
	defer C.free(unsafe.Pointer(a))
	status := C.latch_save(a, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	runtime.KeepAlive(data)
	if status != C.errSecSuccess {
		return ErrKeychain
	}
	return nil
}
func DefaultBackend(dir string) (Backend, string) { return KeychainBackend{}, "keychain" }
