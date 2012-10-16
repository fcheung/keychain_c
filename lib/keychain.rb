class Keychain
  class Error < StandardError
  end

  InternetPasswordItemClass = 'inet' #kSecInternetPasswordItemClass
  GenericPasswordItemClass  = 'genp'


  CreationDateItemAttr        = 'cdat',
  ModDateItemAttr             = 'mdat',
  DescriptionItemAttr         = 'desc',
  CommentItemAttr             = 'icmt',
  CreatorItemAttr             = 'crtr',
  TypeItemAttr                = 'type',
  ScriptCodeItemAttr          = 'scrp',
  LabelItemAttr               = 'labl',
  InvisibleItemAttr           = 'invi',
  NegativeItemAttr            = 'nega',
  CustomIconItemAttr          = 'cusi',
  AccountItemAttr             = 'acct',
  ServiceItemAttr             = 'svce',
  GenericItemAttr             = 'gena',
  SecurityDomainItemAttr      = 'sdmn',
  ServerItemAttr              = 'srvr',
  AuthenticationTypeItemAttr  = 'atyp',
  PortItemAttr                = 'port',
  PathItemAttr                = 'path',
  VolumeItemAttr              = 'vlme',
  AddressItemAttr             = 'addr',
  SignatureItemAttr           = 'ssig',
  ProtocolItemAttr            = 'ptcl',
  CertificateType             = 'ctyp',
  CertificateEncoding         = 'cenc',
  CrlType                     = 'crtp',
  CrlEncoding                 = 'crnc',
  Alias                       = 'alis'

  def inspect
    "<Keychain 0x#{self.object_id.to_s(16)}: #{path}>"
  end
end

require 'keychain/keychain'