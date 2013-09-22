#include "ruby.h"
#include "ruby/encoding.h"
#include <Security/Security.h>

VALUE rb_cKeychain;
VALUE rb_eKeychainError;
VALUE rb_eKeychainDuplicateItemError;
VALUE rb_eKeychainNoSuchKeychainError;
VALUE rb_eKeychainAuthFailedError;
VALUE rb_cKeychainItem;

VALUE rb_cKeychainSecMap;

VALUE rb_cPointerWrapper;
static void CheckOSStatusOrRaise(OSStatus err){
  if(err != 0){
    CFStringRef description = SecCopyErrorMessageString(err, NULL);

    CFIndex bufferSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(description), kCFStringEncodingUTF8);
    char *buffer = malloc(bufferSize + 1);
    CFStringGetCString(description, buffer, bufferSize + 1, kCFStringEncodingUTF8);
    CFRelease(description);

    VALUE exceptionString = rb_enc_str_new(buffer, strlen(buffer), rb_utf8_encoding());
    free(buffer);
    VALUE exception = Qnil;

    switch(err){
      case errSecAuthFailed:
        exception = rb_obj_alloc(rb_eKeychainAuthFailedError);
        break;
      case errSecNoSuchKeychain:
        exception = rb_obj_alloc(rb_eKeychainNoSuchKeychainError);
        break;
      case errSecDuplicateItem:
        exception = rb_obj_alloc(rb_eKeychainDuplicateItemError);
        break;
      default:
        exception = rb_obj_alloc(rb_eKeychainError);
    }
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
  if(rb_enc_get_index(rb_obj_encoding(string))== rb_ascii8bit_encindex()){
    return CFDataCreate(NULL, (UInt8*)RSTRING_PTR(string), RSTRING_LEN(string));
  }
  else{
    string = rb_str_export_to_enc(string, rb_utf8_encoding());
    return CFDataCreate(NULL, (UInt8*)RSTRING_PTR(string), RSTRING_LEN(string));
  }
}

static VALUE cfstring_to_rb_string(CFStringRef s){
  if(CFStringGetTypeID() != CFGetTypeID(s)){
    rb_raise(rb_eTypeError, "Non cfstring passed to cfstring_to_rb_string");
  }
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
  else if(CFDataGetTypeID() == CFGetTypeID(value)){
    CFDataRef data = (CFDataRef)value;
    rubyValue = rb_enc_str_new((const char*)CFDataGetBytePtr(data),CFDataGetLength(data), rb_ascii8bit_encoding());
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
      long long longValue;
      CFNumberGetValue(value, kCFNumberLongLongType, &longValue);
      rubyValue = LL2NUM(longValue);
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
        if(!CFStringCompare(key, kSecValueData,0) || !CFStringCompare(key, kSecAttrGeneric,0)){
          CFDataRef dataValue = rb_create_cf_data(value);
          CFDictionarySetValue(dict,key,dataValue);
          CFRelease(dataValue);
        }
        else{
          CFStringRef stringValue = rb_create_cf_string(value);
          CFDictionarySetValue(dict,key,stringValue);
          CFRelease(stringValue);
        }
      }
      break;
    case T_BIGNUM:
    case T_FIXNUM:
      {
        long long longLongValue = NUM2LL(value);
        CFNumberRef numberValue = CFNumberCreate(NULL,kCFNumberLongLongType,&longLongValue);
        CFDictionarySetValue(dict,key,numberValue);
        CFRelease(numberValue);
        break;
      }
    case T_DATA:
      {
        if(rb_obj_is_kind_of(value, rb_cTime)){
          VALUE floatTime = rb_funcall(value, rb_intern("to_f"),0);
          CFAbsoluteTime abstime = RFLOAT_VALUE(floatTime) - kCFAbsoluteTimeIntervalSince1970;
          CFDateRef cfdate = CFDateCreate(NULL, abstime);
          CFDictionarySetValue(dict, key, cfdate);
          CFRelease(cfdate);
          break;
        }
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

static VALUE rb_create_keychain(int argc, VALUE *argv, VALUE self){
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

  VALUE unsaved = rb_ivar_get(self, rb_intern("unsaved_password"));


  if(!NIL_P(unsaved)){
    return unsaved;
  }
  else{
    OSStatus result = SecKeychainItemCopyAttributesAndData(keychainItem, NULL , NULL, NULL, &dataLength, &data);

    CheckOSStatusOrRaise(result);

    VALUE rb_data = rb_enc_str_new(data, dataLength, rb_ascii8bit_encoding());
    SecKeychainItemFreeAttributesAndData(NULL,data);
    return rb_data;
  }
}

static VALUE add_conditions_to_query(VALUE pair, VALUE r_cfdict, int argc, VALUE argv[]){

  VALUE key = RARRAY_PTR(pair)[0];
  VALUE value = RARRAY_PTR(pair)[1];

  VALUE sec_key = rb_hash_aref(rb_cKeychainSecMap, key);
  if(!NIL_P(sec_key)){
    CFDictionaryRef cfdict;
    Data_Get_Struct(r_cfdict, struct __CFDictionary , cfdict);
    CFStringRef cf_key = rb_create_cf_string(sec_key);
    rb_add_value_to_cf_dictionary((CFMutableDictionaryRef)cfdict, cf_key, value);
    CFRelease(cf_key);
  }
  return Qnil;
}

static VALUE rb_keychain_add_password(VALUE self, VALUE kind, VALUE options){
  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);

  Check_Type(options, T_HASH);
  Check_Type(kind, T_STRING);


  CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  rb_add_value_to_cf_dictionary(attributes, kSecClass, kind);
  CFDictionarySetValue(attributes, kSecReturnAttributes, kCFBooleanTrue);
  CFDictionarySetValue(attributes, kSecReturnRef, kCFBooleanTrue);
  CFDictionarySetValue(attributes, kSecUseKeychain, keychain);

  VALUE rAttributes = Data_Wrap_Struct(rb_cPointerWrapper, NULL, NULL, attributes);

  rb_block_call(options, rb_intern("each"), 0, NULL, RUBY_METHOD_FUNC(add_conditions_to_query), (VALUE)rAttributes);

  CFDictionaryRef result;

  OSStatus status = SecItemAdd(attributes, (CFTypeRef*)&result);
  CFRelease(attributes);
  CheckOSStatusOrRaise(status);

  VALUE rb_keychain_item = rb_keychain_item_from_sec_dictionary(result);
  CFRelease(result);
  return rb_keychain_item;
}


static VALUE copy_attributes_for_update(VALUE pair, VALUE r_cfdict, int argc, VALUE argv[]){

  VALUE key = RARRAY_PTR(pair)[0];
  VALUE value = RARRAY_PTR(pair)[1];

  CFStringRef cf_key = rb_create_cf_string(key);
  if(CFStringCompare(cf_key, kSecAttrCreationDate, 0) &&
     CFStringCompare(cf_key, kSecAttrModificationDate, 0) &&
     CFStringCompare(cf_key, kSecClass, 0)){ /*these values ared read only*/
    
    CFMutableDictionaryRef cfdict;
    Data_Get_Struct(r_cfdict, struct __CFDictionary , cfdict);

    rb_add_value_to_cf_dictionary(cfdict, cf_key, value);
  }
  CFRelease(cf_key);
  
  return Qnil;
}

static CFMutableDictionaryRef sec_query_identifying_item(SecKeychainItemRef item){
  CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  CFArrayRef itemArray = CFArrayCreate(NULL, (const void**)&item, 1, &kCFTypeArrayCallBacks);

  CFDictionarySetValue(query, kSecMatchItemList, itemArray);

  CFRelease(itemArray);

  return query;
}


static CFStringRef rb_copy_item_class(SecKeychainItemRef item){
  SecItemClass secItemClass;
  SecKeychainItemCopyContent(item, &secItemClass, NULL, NULL, NULL);
  secItemClass = CFSwapInt32HostToBig(secItemClass);
  CFStringRef cfclass = CFStringCreateWithBytes(NULL, (UInt8*)&secItemClass, sizeof(secItemClass), kCFStringEncodingUTF8, false);
  return cfclass;
}

static VALUE rb_keychain_item_reload(VALUE self){
  SecKeychainItemRef keychainItem=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainItemRef, keychainItem);

  CFMutableDictionaryRef query = sec_query_identifying_item(keychainItem);

  CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
  CFStringRef cfclass = rb_copy_item_class(keychainItem);
  CFDictionarySetValue(query, kSecClass, cfclass);
  CFRelease(cfclass);

  CFDictionaryRef attributes;
  OSStatus result = SecItemCopyMatching(query, (CFTypeRef*)&attributes);
  CFRelease(query);
  CheckOSStatusOrRaise(result);
  VALUE new_attributes = rb_hash_new();
  CFDictionaryApplyFunction(attributes, cf_hash_to_rb_hash, (void*)new_attributes);
  rb_ivar_set(self, rb_intern("@attributes"), new_attributes);
  rb_ivar_set(self, rb_intern("unsaved_password"), Qnil);
  CFRelease(attributes);

  return self;
}

static VALUE rb_keychain_item_save(VALUE self){
  SecKeychainItemRef keychainItem = NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainItemRef, keychainItem);

  CFMutableDictionaryRef query = sec_query_identifying_item(keychainItem);

  CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  VALUE rb_attributes = rb_ivar_get(self, rb_intern("@attributes"));

  VALUE attributes_wrapper = Data_Wrap_Struct(rb_cPointerWrapper, NULL, NULL, attributes);

  rb_block_call(rb_attributes, rb_intern("each"), 0, NULL, RUBY_METHOD_FUNC(copy_attributes_for_update), (VALUE)attributes_wrapper);

  VALUE newPassword = rb_ivar_get(self, rb_intern("@unsaved_password"));
  if(!NIL_P(newPassword)){
    rb_add_value_to_cf_dictionary(attributes, kSecValueData, newPassword);
  }
  CFStringRef cfclass = rb_copy_item_class(keychainItem);
  CFDictionarySetValue(query, kSecClass, cfclass);
  CFRelease(cfclass);
  
  OSStatus result = SecItemUpdate(query, attributes);

  CFRelease(query);
  CFRelease(attributes);
  CheckOSStatusOrRaise(result);
  rb_keychain_item_reload(self);
  return self;
}




static VALUE rb_keychain_find(int argc, VALUE *argv, VALUE self){

  VALUE kind;
  VALUE attributes;
  VALUE first_or_all;
  rb_scan_args(argc, argv, "2:", &first_or_all, &kind, &attributes);

  Check_Type(first_or_all, T_SYMBOL);
  Check_Type(kind, T_STRING);
  
  CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
  CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
  

  if(rb_to_id(first_or_all) == rb_intern("all")){
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
  }

  rb_add_value_to_cf_dictionary(query, kSecClass, kind);


  if(!NIL_P(attributes)){
    Check_Type(attributes, T_HASH);
    VALUE rb_keychains = rb_hash_aref(attributes, ID2SYM(rb_intern("keychains")));
    if(!NIL_P(rb_keychains)){
      Check_Type(rb_keychains, T_ARRAY);
      CFMutableArrayRef searchArray = CFArrayCreateMutable(NULL, RARRAY_LEN(rb_keychains), &kCFTypeArrayCallBacks);
      for(int index=0; index < RARRAY_LEN(rb_keychains); index++){
        SecKeychainRef keychain = NULL;
        Data_Get_Struct(RARRAY_PTR(rb_keychains)[index], struct OpaqueSecKeychainRef, keychain);
        CFArrayAppendValue(searchArray, keychain);
      }
      CFDictionarySetValue(query, kSecMatchSearchList,searchArray);
      CFRelease(searchArray);
    }  

    VALUE limit = rb_hash_aref(attributes, ID2SYM(rb_intern("limit")));
    if(!NIL_P(limit)){
      Check_Type(limit, T_FIXNUM);
      long c_limit = FIX2LONG(limit);
      CFNumberRef cf_limit = CFNumberCreate(NULL, kCFNumberLongType, &c_limit);
      CFDictionarySetValue(query, kSecMatchLimit, cf_limit);
      CFRelease(cf_limit);
    }

    VALUE conditions = rb_hash_aref(attributes, ID2SYM(rb_intern("conditions")));
    
    if(!NIL_P(conditions)){
      Check_Type(conditions, T_HASH);
      VALUE rQuery = Data_Wrap_Struct(rb_cPointerWrapper, NULL, NULL, query);
      rb_block_call(conditions, rb_intern("each"), 0, NULL, RUBY_METHOD_FUNC(add_conditions_to_query), rQuery);
    }
  }

  CFDictionaryRef result;

  OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)&result);
  CFRelease(query);

  VALUE rb_item = rb_ary_new2(0);

  switch(status){
    case errSecItemNotFound: 
      break;
    default:
    CheckOSStatusOrRaise(status);
    if(CFArrayGetTypeID() == CFGetTypeID(result)){
      CFArrayRef result_array = (CFArrayRef)result;
      for(CFIndex i = 0; i < CFArrayGetCount(result_array); i++){
        rb_ary_push(rb_item,rb_keychain_item_from_sec_dictionary(CFArrayGetValueAtIndex(result_array,i)));
      }
    }
    else{
      rb_ary_push(rb_item, rb_keychain_item_from_sec_dictionary(result));
    }
    CFRelease(result);
  }

  if(rb_to_id(first_or_all) == rb_intern("first")){
    return rb_ary_entry(rb_item,0);
  }
  else{
    return rb_item;
  }
}

static void build_keychain_sec_map(void){
  rb_cKeychainSecMap = rb_hash_new();
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("created_at")), cfstring_to_rb_string(kSecAttrCreationDate));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("updated_at")), cfstring_to_rb_string(kSecAttrModificationDate));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("description")), cfstring_to_rb_string(kSecAttrDescription));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("comment")), cfstring_to_rb_string(kSecAttrComment));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("account")), cfstring_to_rb_string(kSecAttrAccount));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("service")), cfstring_to_rb_string(kSecAttrService));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("server")), cfstring_to_rb_string(kSecAttrServer));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("port")), cfstring_to_rb_string(kSecAttrPort));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("security_domain")), cfstring_to_rb_string(kSecAttrSecurityDomain));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("negative")), cfstring_to_rb_string(kSecAttrIsNegative));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("invisible")), cfstring_to_rb_string(kSecAttrIsInvisible));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("label")), cfstring_to_rb_string(kSecAttrLabel));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("path")), cfstring_to_rb_string(kSecAttrPath));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("protocol")), cfstring_to_rb_string(kSecAttrProtocol));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("password")), cfstring_to_rb_string(kSecValueData));
  rb_hash_aset(rb_cKeychainSecMap, ID2SYM(rb_intern("klass")), cfstring_to_rb_string(kSecClass));

  rb_const_set(rb_cKeychain, rb_intern("KEYCHAIN_MAP"), rb_cKeychainSecMap);
}

static void build_classes(void){
  VALUE classes = rb_define_module_under(rb_cKeychainItem, "Classes");
  rb_const_set(classes, rb_intern("INTERNET"), cfstring_to_rb_string(kSecClassInternetPassword));
  rb_const_set(classes, rb_intern("GENERIC"), cfstring_to_rb_string(kSecClassGenericPassword));
}

static void build_protocols(void){
  VALUE protocols = rb_define_module_under(rb_cKeychain, "Protocols");

  rb_const_set(protocols, rb_intern("FTP"), INT2NUM(kSecProtocolTypeFTP       ));
  rb_const_set(protocols, rb_intern("FTPAccount"), INT2NUM(kSecProtocolTypeFTPAccount));
  rb_const_set(protocols, rb_intern("HTTP"), INT2NUM(kSecProtocolTypeHTTP      ));
  rb_const_set(protocols, rb_intern("IRC"), INT2NUM(kSecProtocolTypeIRC       ));
  rb_const_set(protocols, rb_intern("NNTP"), INT2NUM(kSecProtocolTypeNNTP      ));
  rb_const_set(protocols, rb_intern("POP3"), INT2NUM(kSecProtocolTypePOP3      ));
  rb_const_set(protocols, rb_intern("SMTP"), INT2NUM(kSecProtocolTypeSMTP      ));
  rb_const_set(protocols, rb_intern("SOCKS"), INT2NUM(kSecProtocolTypeSOCKS     ));
  rb_const_set(protocols, rb_intern("IMAP"), INT2NUM(kSecProtocolTypeIMAP      ));
  rb_const_set(protocols, rb_intern("LDAP"), INT2NUM(kSecProtocolTypeLDAP      ));
  rb_const_set(protocols, rb_intern("AppleTalk"), INT2NUM(kSecProtocolTypeAppleTalk ));
  rb_const_set(protocols, rb_intern("AFP"), INT2NUM(kSecProtocolTypeAFP       ));
  rb_const_set(protocols, rb_intern("Telnet"), INT2NUM(kSecProtocolTypeTelnet    ));
  rb_const_set(protocols, rb_intern("SSH"), INT2NUM(kSecProtocolTypeSSH       ));
  rb_const_set(protocols, rb_intern("FTPS"), INT2NUM(kSecProtocolTypeFTPS      ));
  rb_const_set(protocols, rb_intern("HTTPS"), INT2NUM(kSecProtocolTypeHTTPS     ));
  rb_const_set(protocols, rb_intern("HTTPProxy"), INT2NUM(kSecProtocolTypeHTTPProxy ));
  rb_const_set(protocols, rb_intern("HTTPSProxy"), INT2NUM(kSecProtocolTypeHTTPSProxy));
  rb_const_set(protocols, rb_intern("FTPProxy "), INT2NUM(kSecProtocolTypeFTPProxy  ));
  rb_const_set(protocols, rb_intern("CIFS"), INT2NUM(kSecProtocolTypeCIFS      ));
  rb_const_set(protocols, rb_intern("SMB"), INT2NUM(kSecProtocolTypeSMB       ));
  rb_const_set(protocols, rb_intern("RTSP "), INT2NUM(kSecProtocolTypeRTSP      ));
  rb_const_set(protocols, rb_intern("RTSPProxy"), INT2NUM(kSecProtocolTypeRTSPProxy ));
  rb_const_set(protocols, rb_intern("DAAP"), INT2NUM(kSecProtocolTypeDAAP      ));
  rb_const_set(protocols, rb_intern("EPPC"), INT2NUM(kSecProtocolTypeEPPC      ));
  rb_const_set(protocols, rb_intern("IPP"), INT2NUM(kSecProtocolTypeIPP       ));
  rb_const_set(protocols, rb_intern("NNTPS"), INT2NUM(kSecProtocolTypeNNTPS     ));
  rb_const_set(protocols, rb_intern("LDAPS"), INT2NUM(kSecProtocolTypeLDAPS     ));
  rb_const_set(protocols, rb_intern("TelnetS"), INT2NUM(kSecProtocolTypeTelnetS   ));
  rb_const_set(protocols, rb_intern("IMAPS"), INT2NUM(kSecProtocolTypeIMAPS     ));
  rb_const_set(protocols, rb_intern("IRCS"), INT2NUM(kSecProtocolTypeIRCS      ));
  rb_const_set(protocols, rb_intern("POP3S"), INT2NUM(kSecProtocolTypePOP3S     ));
  rb_const_set(protocols, rb_intern("CVSpserver"), INT2NUM(kSecProtocolTypeCVSpserver));
  rb_const_set(protocols, rb_intern("SVN"), INT2NUM(kSecProtocolTypeSVN       ));
  rb_const_set(protocols, rb_intern("ANY"), INT2NUM(kSecProtocolTypeAny       ));
}


static void rb_get_keychain_settings(VALUE self, SecKeychainSettings *settings){
  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);
  settings->version = SEC_KEYCHAIN_SETTINGS_VERS1;
  OSStatus result = SecKeychainCopySettings(keychain, settings);
  CheckOSStatusOrRaise(result);
}

static void rb_set_keychain_settings(VALUE self, SecKeychainSettings *settings){
  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);
  OSStatus result = SecKeychainSetSettings(keychain, settings);
  CheckOSStatusOrRaise(result);
}

static VALUE rb_keychain_settings_lock_on_sleep(VALUE self){
  SecKeychainSettings settings;
  rb_get_keychain_settings(self, &settings);
  return settings.lockOnSleep ? Qtrue : Qfalse;
}

static VALUE rb_keychain_settings_set_lock_on_sleep(VALUE self, VALUE newValue){
  SecKeychainSettings settings;
  rb_get_keychain_settings(self, &settings);
  settings.lockOnSleep = RTEST(newValue);
  rb_set_keychain_settings(self, &settings);
  return newValue;
}

static VALUE rb_keychain_settings_lock_interval(VALUE self){
  SecKeychainSettings settings;
  rb_get_keychain_settings(self, &settings);
  return UINT2NUM(settings.lockInterval);
}

static VALUE rb_keychain_settings_set_lock_interval(VALUE self, VALUE newValue){
  SecKeychainSettings settings;
  rb_get_keychain_settings(self, &settings);
  settings.lockInterval = NUM2UINT(newValue);
  rb_set_keychain_settings(self, &settings);
  return newValue;
}

static VALUE rb_keychain_lock(VALUE self){
  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);
  OSStatus result = SecKeychainLock(keychain);
  CheckOSStatusOrRaise(result);

  return Qnil;
}

static VALUE rb_keychain_unlock(int argc, VALUE *argv, VALUE self){
  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);

  VALUE password;
  rb_scan_args(argc, argv, "01", &password);

  OSStatus result = noErr;
  if(password){
    StringValue(password);
    password = rb_str_export_to_enc(password, rb_utf8_encoding());

    result = SecKeychainUnlock(keychain, (UInt32)RSTRING_LEN(password), (UInt8*)RSTRING_PTR(password), true);
  }else{
    result = SecKeychainUnlock(keychain,0,NULL,false);
  }

  CheckOSStatusOrRaise(result);

  return Qnil;
}

static VALUE rb_keychain_status(VALUE self){
  UInt32 status;
  SecKeychainRef keychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);
  OSStatus result = SecKeychainGetStatus(keychain, &status);
  CheckOSStatusOrRaise(result);
  return UINT2NUM(status);
}

static VALUE rb_keychain_item_keychain(VALUE self){
  SecKeychainRef keychain=NULL;
  SecKeychainItemRef item=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainItemRef, item);
  OSStatus result = SecKeychainItemCopyKeychain(item,&keychain);
  CheckOSStatusOrRaise(result);
  return KeychainFromSecKeychainRef(keychain);
}

static VALUE rb_keychain_compare(VALUE self, VALUE other){
  SecKeychainRef keychain=NULL;
  SecKeychainRef otherKeychain=NULL;
  Data_Get_Struct(self, struct OpaqueSecKeychainRef, keychain);
  Data_Get_Struct(other, struct OpaqueSecKeychainRef, otherKeychain);

  return CFEqual(keychain, otherKeychain);
}

void Init_keychain(){
  rb_cKeychain = rb_const_get(rb_cObject, rb_intern("Keychain"));
  rb_eKeychainError = rb_const_get(rb_cKeychain, rb_intern("Error"));
  rb_eKeychainDuplicateItemError = rb_const_get(rb_cKeychain, rb_intern("DuplicateItemError"));
  rb_eKeychainNoSuchKeychainError = rb_const_get(rb_cKeychain, rb_intern("NoSuchKeychainError"));
  rb_eKeychainAuthFailedError = rb_const_get(rb_cKeychain, rb_intern("AuthFailedError"));

  build_keychain_sec_map();
  build_protocols();

  rb_define_singleton_method(rb_cKeychain, "default", RUBY_METHOD_FUNC(rb_default_keychain), 0);
  rb_define_singleton_method(rb_cKeychain, "open", RUBY_METHOD_FUNC(rb_open_keychain), 1);
  rb_define_singleton_method(rb_cKeychain, "create", RUBY_METHOD_FUNC(rb_create_keychain), -1);

  rb_define_singleton_method(rb_cKeychain, "find", RUBY_METHOD_FUNC(rb_keychain_find), -1);

  rb_define_method(rb_cKeychain, "==", RUBY_METHOD_FUNC(rb_keychain_compare), 1);

  rb_define_method(rb_cKeychain, "lock!", RUBY_METHOD_FUNC(rb_keychain_lock), 0);
  rb_define_method(rb_cKeychain, "unlock!", RUBY_METHOD_FUNC(rb_keychain_unlock), -1);

  rb_define_method(rb_cKeychain, "delete", RUBY_METHOD_FUNC(rb_keychain_delete), 0);
  rb_define_method(rb_cKeychain, "path", RUBY_METHOD_FUNC(rb_keychain_path), 0);
  rb_define_method(rb_cKeychain, "add_password", RUBY_METHOD_FUNC(rb_keychain_add_password), 2);

  rb_define_method(rb_cKeychain, "lock_on_sleep?", RUBY_METHOD_FUNC(rb_keychain_settings_lock_on_sleep), 0);
  rb_define_method(rb_cKeychain, "lock_on_sleep=", RUBY_METHOD_FUNC(rb_keychain_settings_set_lock_on_sleep), 1);
  
  rb_define_method(rb_cKeychain, "lock_interval", RUBY_METHOD_FUNC(rb_keychain_settings_lock_interval), 0);
  rb_define_method(rb_cKeychain, "lock_interval=", RUBY_METHOD_FUNC(rb_keychain_settings_set_lock_interval), 1);

  rb_define_method(rb_cKeychain, "status", RUBY_METHOD_FUNC(rb_keychain_status), 0);

//we don't bother with use_lock_interval - the underlying api appears to ignore it ( see http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55050.9/lib/SecKeychain.cpp )
  rb_cKeychainItem = rb_define_class_under(rb_cKeychain, "Item", rb_cObject);
  rb_define_method(rb_cKeychainItem, "keychain", RUBY_METHOD_FUNC(rb_keychain_item_keychain), 0);

  rb_define_method(rb_cKeychainItem, "delete", RUBY_METHOD_FUNC(rb_keychain_item_delete), 0);
  rb_define_method(rb_cKeychainItem, "password", RUBY_METHOD_FUNC(rb_keychain_item_copy_password), 0);

  rb_define_method(rb_cKeychainItem, "save!", RUBY_METHOD_FUNC(rb_keychain_item_save), 0);

  build_classes();

  rb_cPointerWrapper  = rb_define_class_under(rb_cKeychain, "PointerWrapper", rb_cObject);

}