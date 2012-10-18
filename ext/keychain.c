#include "ruby.h"
#include "ruby/encoding.h"
#include <Security/Security.h>

VALUE rb_cKeychain;
VALUE rb_cKeychainError;
VALUE rb_cKeychainItem;

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
  OSStatus result =SecKeychainCopyDefault(&keychain);
  CheckOSStatusOrRaise(result);

  return KeychainFromSecKeychainRef(keychain);
}

static VALUE rb_open_keychain(VALUE self, VALUE path){
  SecKeychainRef keychain=NULL;
  OSStatus result =SecKeychainOpen(StringValueCStr(path), &keychain);
  CheckOSStatusOrRaise(result);

  return KeychainFromSecKeychainRef(keychain);
}

static VALUE rb_new_keychain(int argc, VALUE *argv, VALUE self){
  VALUE password, path;
  rb_scan_args(argc, argv, "11", &path, &password);

  char * c_password = NULL;
  UInt32 passwordLength = 0;
  if(!NIL_P(password)){
    password = rb_str_conv_enc(password, (rb_encoding*)rb_obj_encoding(password), rb_utf8_encoding());
    c_password = StringValueCStr(password);
    passwordLength = (UInt32)strlen(c_password);
  }

  SecKeychainRef keychain;
  OSStatus result =SecKeychainCreate(StringValueCStr(path), passwordLength, c_password, c_password == NULL, NULL, &keychain);
  CheckOSStatusOrRaise(result);

  return KeychainFromSecKeychainRef(keychain);

}

static VALUE rb_keychain_path(VALUE self){
  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);
  UInt32 pathLength = PATH_MAX;
  char path[PATH_MAX];
  OSStatus result = SecKeychainGetPath(keychain, &pathLength, path);

  CheckOSStatusOrRaise(result);
  return rb_enc_str_new(path, pathLength, rb_utf8_encoding());
}

static VALUE rb_keychain_delete(VALUE self){

  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);
  OSStatus result = SecKeychainDelete(keychain);
  CheckOSStatusOrRaise(result);
  return self;
}

static VALUE rb_keychain_item_delete(VALUE self){

  SecKeychainItemRef keychainItem=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainItemRef, keychainItem);
  OSStatus result = SecKeychainItemDelete(keychainItem);
  CheckOSStatusOrRaise(result);
  return self;
}

static VALUE cfstring_to_rb_string(CFStringRef s){
  const char * fastBuffer = CFStringGetCStringPtr(s, kCFStringEncodingUTF8);
  if(fastBuffer){
    return rb_enc_str_new(fastBuffer, strlen(fastBuffer), rb_utf8_encoding());
  }else{
    CFIndex bufferLength = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s),kCFStringEncodingUTF8);
    char * buffer = malloc(bufferLength);
    CFIndex used = 0;
    CFStringGetBytes(s,CFRangeMake(0, CFStringGetLength(s)), kCFStringEncodingUTF8, 0, false, (UInt8*)buffer, bufferLength, &used);
    VALUE rb_string = rb_enc_str_new(buffer, used, rb_utf8_encoding());
    free(buffer);
    return rb_string;
  }
}


static void cf_hash_to_rb_hash(const void *raw_key, const void * raw_value, void *ctx){
  CFTypeRef value = (CFTypeRef)raw_value;
  CFStringRef key = (CFStringRef)raw_key;

  VALUE rubyValue = Qnil;
  VALUE hash = (VALUE)ctx;

  if(CFStringGetTypeID() == CFGetTypeID(value)){
    rubyValue = cfstring_to_rb_string((CFStringRef)value);
  }
  else if(CFBooleanGetTypeID() == CFGetTypeID(value)){
    Boolean booleanValue = CFBooleanGetValue(value);
    rubyValue = booleanValue ? Qtrue : Qfalse;
  }
  else if(CFNumberGetTypeID() == CFGetTypeID(value)){
    if(CFNumberIsFloatType(value))
    {
      double doubleValue;
      CFNumberGetValue(value, kCFNumberDoubleType, &doubleValue);
      rubyValue = rb_float_new(doubleValue);
    }else{
      long longValue;
      CFNumberGetValue(value, kCFNumberLongType, &longValue);
      rubyValue = LONG2NUM(longValue);
    }
  }
  else if (CFDateGetTypeID() == CFGetTypeID(value)){
    CFDateRef date = (CFDateRef) value;
    CFAbsoluteTime abs_time = CFDateGetAbsoluteTime(date);
    double secondsSinceUnixEpoch = abs_time + kCFAbsoluteTimeIntervalSince1970;
    time_t seconds = (time_t)secondsSinceUnixEpoch;
    long usec = (secondsSinceUnixEpoch - seconds) * 1000000;
    rubyValue = rb_time_new((time_t)secondsSinceUnixEpoch, usec);
  }

  if(!NIL_P(rubyValue)){
    rb_hash_aset(hash, cfstring_to_rb_string(key), rubyValue);
  }
}

static VALUE rb_keychain_item_copy_attributes(VALUE self){

  SecKeychainItemRef keychainItem=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainItemRef, keychainItem);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFArrayRef itemsToSearch = CFArrayCreate(NULL, (const void**)&keychainItem, 1, &kCFTypeArrayCallBacks);

  CFDictionaryAddValue(query, kSecMatchItemList, itemsToSearch);
  CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFRelease(itemsToSearch);
  CFDictionaryRef result;
  OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)&result);
  CFRelease(query);
  CheckOSStatusOrRaise(status);

  VALUE attributes = rb_hash_new();
  CFDictionaryApplyFunction(result, cf_hash_to_rb_hash, (void*)attributes);
  CFRelease(result);
  return attributes;

}

static VALUE rb_keychain_item_copy_password(VALUE self){
  void *data;
  SecKeychainItemRef keychainItem=NULL;
  UInt32 dataLength;
  Data_Get_Struct(self, struct OpaqueSecKeychainItemRef, keychainItem);

  OSStatus result = SecKeychainItemCopyAttributesAndData(keychainItem, NULL , NULL, NULL, &dataLength, &data);

  CheckOSStatusOrRaise(result);

  VALUE rb_data = rb_enc_str_new(data, dataLength, rb_ascii8bit_encoding());
  SecKeychainItemFreeAttributesAndData(NULL,data);
  return rb_data;
}


static VALUE rb_keychain_add_generic_password(VALUE self, VALUE rb_service, VALUE rb_account, VALUE rb_password){
  SecKeychainItemRef keychainItem = NULL;
  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);

  VALUE utf_service = rb_str_conv_enc(rb_service, (rb_encoding*)rb_obj_encoding(rb_service), rb_utf8_encoding()); 
  VALUE utf_account = rb_str_conv_enc(rb_account, (rb_encoding*)rb_obj_encoding(rb_account), rb_utf8_encoding()); 
  VALUE utf_password = rb_str_conv_enc(rb_password, (rb_encoding*)rb_obj_encoding(rb_password), rb_utf8_encoding()); 

  OSStatus result = SecKeychainAddGenericPassword(keychain,
                        (UInt32)RSTRING_LEN(utf_service),
                        RSTRING_PTR(utf_service),
                        (UInt32)RSTRING_LEN(utf_account),
                        RSTRING_PTR(utf_account),
                        (UInt32)RSTRING_LEN(utf_password),
                        RSTRING_PTR(utf_password),
                        &keychainItem);

  CheckOSStatusOrRaise(result);
  return Data_Wrap_Struct(rb_cKeychainItem, NULL, CFRelease, keychainItem);
}

static VALUE rb_search_keychain(int argc, VALUE *argv, VALUE self){
  VALUE arrayOrKeychainsOrNil;
  VALUE attributes;

  rb_scan_args(argc, argv, "01:", &arrayOrKeychainsOrNil, &attributes);

  CFTypeRef keychainsToSearch = NULL;
  
  switch (TYPE(arrayOrKeychainsOrNil)) {
    case T_NIL:
      break;
    case T_ARRAY:
    { 
      CFMutableArrayRef searchArray = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
      for(int index=0; index < RARRAY_LEN(arrayOrKeychainsOrNil); index++){
        SecKeychainRef keychain = NULL;
        Data_Get_Struct(RARRAY_PTR(arrayOrKeychainsOrNil)[index], struct OpaqueSecKeychainRef, keychain);
        CFArrayAppendValue(searchArray, keychain);
      }
      keychainsToSearch = searchArray;
    }  
      break;

    case T_DATA:
      Data_Get_Struct(arrayOrKeychainsOrNil, struct OpaqueSecKeychainRef, keychainsToSearch);
      CFRetain(keychainsToSearch);
      break;
    default:
      rb_raise(rb_eTypeError, "searchPath should be a keychain, array of keychains or NULL was %d",TYPE(arrayOrKeychainsOrNil));
      break;
  }

  UInt32 service_length = 0;
  char * service_data = NULL;
  UInt32 account_length = 0;
  char * account_data = NULL;
  
  if(attributes){
    VALUE rb_service = rb_hash_aref(attributes, ID2SYM(rb_intern("service")));
    if(RTEST(rb_service)){
      StringValue(rb_service);
      service_length = (UInt32)RSTRING_LEN(rb_service);
      service_data = malloc(service_length);
      memcpy(service_data, RSTRING_PTR(rb_service), service_length);
    }

    VALUE rb_account = rb_hash_aref(attributes, ID2SYM(rb_intern("account")));
    if(RTEST(rb_account)){
      StringValue(rb_account);
      account_length = (UInt32)RSTRING_LEN(rb_account);
      account_data = malloc(account_length);
      memcpy(account_data, RSTRING_PTR(rb_account), account_length);
    }
  }

  SecKeychainItemRef item = NULL;

  void *passwordData;
  UInt32 passwordLength;
  OSStatus result = SecKeychainFindGenericPassword(keychainsToSearch,  service_length, service_data, account_length, account_data, NULL, NULL, &item);

  if(keychainsToSearch){
    CFRelease(keychainsToSearch);
  }
  if(service_data){
    free(service_data);
    service_data = NULL;
  }
  if(account_data){
    free(account_data);
    account_data = NULL;
  }

  if(result == errSecItemNotFound){
    return Qnil;
  }else{
    CheckOSStatusOrRaise(result);
  }

  return Data_Wrap_Struct(rb_cKeychainItem, NULL, CFRelease, item);
}

void Init_keychain(){
  rb_cKeychain = rb_const_get(rb_cObject, rb_intern("Keychain"));
  rb_cKeychainError = rb_const_get(rb_cKeychain, rb_intern("Error"));

  rb_define_singleton_method(rb_cKeychain, "default", RUBY_METHOD_FUNC(rb_default_keychain), 0);
  rb_define_singleton_method(rb_cKeychain, "open", RUBY_METHOD_FUNC(rb_open_keychain), 1);
  rb_define_singleton_method(rb_cKeychain, "new", RUBY_METHOD_FUNC(rb_new_keychain), -1);

  rb_define_singleton_method(rb_cKeychain, "search", RUBY_METHOD_FUNC(rb_search_keychain), -1);

  rb_define_method(rb_cKeychain, "delete", RUBY_METHOD_FUNC(rb_keychain_delete), 0);

  rb_define_method(rb_cKeychain, "path", RUBY_METHOD_FUNC(rb_keychain_path), 0);
  rb_define_method(rb_cKeychain, "add_generic_password", RUBY_METHOD_FUNC(rb_keychain_add_generic_password), 3);

  rb_cKeychainItem = rb_define_class_under(rb_cKeychain, "Item", rb_cObject);

  rb_define_method(rb_cKeychainItem, "delete", RUBY_METHOD_FUNC(rb_keychain_item_delete), 0);
  rb_define_method(rb_cKeychainItem, "copy_attributes", RUBY_METHOD_FUNC(rb_keychain_item_copy_attributes), 0);
  rb_define_method(rb_cKeychainItem, "password", RUBY_METHOD_FUNC(rb_keychain_item_copy_password), 0);



}