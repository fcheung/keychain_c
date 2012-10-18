class Keychain
  class Error < StandardError
    attr_accessor :code
    def initialize(message, code)
      self.code = code
      super message
    end

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

  def search(attributes={})
    self.class.search([self], attributes)
  end
end

require 'keychain/keychain'

class Keychain::Item

  KEYCHAIN_MAP = {
    'cdat' => :created_at,
    'mdat' => :updated_at,
    'desc' => :description,
    'icmt' => :comment,
    'nega' => :negative,
    'acct' => :account,
    'svce' => :service,
    'sdmn' => :security_domain,
    'srvr' => :host,
    'port' => :port,
    'path' => :path,
    'protocol' => :protocol
  }

  KEYCHAIN_INVERSE_MAP = KEYCHAIN_MAP.invert

  def attributes
    @attributes ||= copy_attributes
  end

  KEYCHAIN_INVERSE_MAP.each do |ruby_name, attr_name|
    define_method ruby_name do
      attributes[attr_name]
    end
    define_method ruby_name.to_s+'=' do |value|
      attributes[attr_name] = value
    end
  end
end
