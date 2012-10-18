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

static CFStringRef rb_create_cf_string(VALUE string){
  StringValue(string);
  string = rb_str_export_to_enc(string, rb_utf8_encoding());
  char * c_string= StringValueCStr(string);
  return CFStringCreateWithCString(NULL, c_string, kCFStringEncodingUTF8);
}

static CFDataRef rb_create_cf_data(VALUE string){
  StringValue(string);
  string = rb_str_export_to_enc(string, rb_utf8_encoding());
  char * c_string= StringValueCStr(string);
  return CFDataCreate(NULL, (UInt8*)c_string, strlen(c_string));
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

VALUE rb_keychain_item_from_sec_dictionary(CFDictionaryRef dict){
  SecKeychainItemRef item = (SecKeychainItemRef) CFDictionaryGetValue(dict, kSecValueRef);
  CFRetain(item);
  VALUE rb_item = Data_Wrap_Struct(rb_cKeychainItem, NULL, CFRelease, item);
  VALUE keychain_item_attributes = rb_hash_new();
  CFDictionaryApplyFunction(dict, cf_hash_to_rb_hash, (void*)keychain_item_attributes);
  rb_ivar_set(rb_item, rb_intern("@attributes"), keychain_item_attributes);
  return rb_item;
}

static void rb_add_value_to_cf_dictionary(CFMutableDictionaryRef dict, CFStringRef key, VALUE value){
  switch(TYPE(value)){
    case T_STRING:
      {
        CFStringRef stringValue = rb_create_cf_string(value);
        CFDictionaryAddValue(dict,key,stringValue);
        CFRelease(stringValue);
      }
      break;
    case T_FIXNUM:
      {
        long value = FIX2LONG(value);
        CFNumberRef numberValue = CFNumberCreate(NULL,kCFNumberLongType,&value);
        CFDictionaryAddValue(dict,key,numberValue);
        CFRelease(numberValue);
        break;
      }
    default:
      rb_raise(rb_eTypeError, "Can't convert value to cftype: %s", rb_obj_classname(value));
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

  
  CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  CFDictionaryAddValue(attributes, kSecReturnAttributes, kCFBooleanTrue);
  CFDictionaryAddValue(attributes, kSecReturnRef, kCFBooleanTrue);
  CFDictionaryAddValue(attributes, kSecClass, kSecClassGenericPassword);

  CFDictionaryAddValue(attributes, kSecUseKeychain, keychain);

  rb_add_value_to_cf_dictionary(attributes, kSecAttrService, rb_service);
  rb_add_value_to_cf_dictionary(attributes, kSecAttrAccount, rb_account);

  CFDataRef passwordData= rb_create_cf_data(rb_password);
  CFDictionaryAddValue(attributes, kSecValueData, passwordData);
  CFRelease(passwordData);
  
  CFDictionaryRef result;
  OSStatus status = SecItemAdd(attributes, (CFTypeRef*)&result);
  CFRelease(attributes);
  CheckOSStatusOrRaise(status);

  VALUE rb_keychain_item = rb_keychain_item_from_sec_dictionary(result);
  CFRelease(result);
  return rb_keychain_item;
}


static VALUE rb_search_keychain(int argc, VALUE *argv, VALUE self){
  VALUE arrayOrKeychainsOrNil;
  VALUE attributes;

  rb_scan_args(argc, argv, "01:", &arrayOrKeychainsOrNil, &attributes);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFArrayRef keychainsToSearch = NULL;
  
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
    default:
      rb_raise(rb_eTypeError, "searchPath should be a keychain, array of keychains or NULL was %d",TYPE(arrayOrKeychainsOrNil));
      break;
  }
  if(keychainsToSearch){
    CFDictionaryAddValue(query, kSecMatchSearchList, keychainsToSearch);
    CFRelease(keychainsToSearch);
  }

  CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);

  
  if(attributes){
    VALUE rb_service = rb_hash_aref(attributes, ID2SYM(rb_intern("service")));
    if(RTEST(rb_service)){
      CFStringRef service = rb_create_cf_string(rb_service);
      CFDictionaryAddValue(query, kSecAttrService, service);
      CFRelease(service);
    }

    VALUE rb_account = rb_hash_aref(attributes, ID2SYM(rb_intern("account")));
    if(RTEST(rb_account)){
      CFStringRef account = rb_create_cf_string(rb_account);
      CFDictionaryAddValue(query, kSecAttrAccount, account);
      CFRelease(account);
    }

  }

  CFDictionaryRef result;
  OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)&result);
  CFRelease(query);

  if(status == errSecItemNotFound){
    return Qnil;
  }else{
    CheckOSStatusOrRaise(status);
  }

  VALUE rb_item = rb_keychain_item_from_sec_dictionary(result);
  CFRelease(result);
  return rb_item;
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
  rb_define_method(rb_cKeychainItem, "password", RUBY_METHOD_FUNC(rb_keychain_item_copy_password), 0);



}