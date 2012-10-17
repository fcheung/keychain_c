#include "ruby.h"
#include "ruby/encoding.h"
#include <Security/Security.h>

VALUE rb_cKeychain;
VALUE rb_cKeychainError;

static void CheckOSStatusOrRaise(OSStatus err){
  if(err != 0){
    CFStringRef description = SecCopyErrorMessageString(err, NULL);

    CFIndex bufferSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(description), kCFStringEncodingUTF8);
    char *buffer = malloc(bufferSize + 1);
    CFStringGetCString(description, buffer, bufferSize + 1, kCFStringEncodingUTF8);
    CFRelease(description);

    VALUE exceptionString = rb_enc_str_new(buffer, strlen(buffer), rb_utf8_encoding());
    free(buffer);
    VALUE exception = rb_obj_alloc(rb_cKeychainError);
    rb_funcall(exception, rb_intern("initialize"), 2,exceptionString, INT2FIX(err));
    rb_exc_raise(exception);
  }
}
static VALUE KeychainFromSecKeychainRef(SecKeychainRef keychainRef){
  VALUE result = Data_Wrap_Struct(rb_cKeychain, NULL, CFRelease, keychainRef);
  return result;
}

static VALUE rb_default_keychain(VALUE self){
  SecKeychainRef keychain=NULL;
  SecKeychainCopyDefault(&keychain);

  return KeychainFromSecKeychainRef(keychain);
}

static VALUE rb_open_keychain(VALUE self, VALUE path){
  SecKeychainRef keychain=NULL;
  SecKeychainOpen(StringValueCStr(path), &keychain);

  return KeychainFromSecKeychainRef(keychain);
}

static VALUE rb_keychain_path(VALUE self){
  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);
  UInt32 pathLength = PATH_MAX;
  char path[PATH_MAX];
  OSStatus result = SecKeychainGetPath(keychain, &pathLength, path);

  CheckOSStatusOrRaise(result);
  return rb_str_new(path, pathLength);

}
void Init_keychain(){
  rb_cKeychain = rb_const_get(rb_cObject, rb_intern("Keychain"));
  rb_cKeychainError = rb_const_get(rb_cKeychain, rb_intern("Error"));

  rb_define_singleton_method(rb_cKeychain, "default", RUBY_METHOD_FUNC(rb_default_keychain), 0);
  rb_define_singleton_method(rb_cKeychain, "new", RUBY_METHOD_FUNC(rb_open_keychain), 1);

  rb_define_method(rb_cKeychain, "path", RUBY_METHOD_FUNC(rb_keychain_path), 0);

}