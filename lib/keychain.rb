class Keychain
  class Proxy
    def initialize(kind, attributes={})
      @stored_attributes = attributes
      @kind = kind
    end

    def find(first_or_all, attributes = {})
      Keychain.find(first_or_all, @kind, @stored_attributes.merge(attributes))
    end

    def add options={}
      keychain = (@stored_attributes[:keychains] && @stored_attributes[:keychains].first) || Keychain.default
      keychain.add_password @kind, options
    end
  end

  class Error < StandardError
    attr_accessor :code
    def initialize(message, code)
      self.code = code
      super message
    end
  end
  class DuplicateItemError < Error; end


  def inspect
    "<Keychain 0x#{self.object_id.to_s(16)}: #{path}>"
  end

  def generic_passwords
    Proxy.new(Item::Classes::GENERIC,:keychains => [self])
  end

  def internet_passwords
    Proxy.new(Item::Classes::INTERNET,:keychains => [self])
  end

  def self.generic_passwords
    Proxy.new(Item::Classes::GENERIC)
  end

  def self.internet_passwords
    Proxy.new(Item::Classes::INTERNET)
  end

end

require 'keychain/keychain'

class Keychain::Item

  Keychain::KEYCHAIN_MAP.each do |ruby_name, attr_name|
    unless method_defined?(ruby_name)
      define_method ruby_name do
        @attributes[attr_name]
      end
      define_method ruby_name.to_s+'=' do |value|
        @attributes[attr_name] = value
      end
    end
  end

  def password=(new_password)
    @unsaved_password = new_password
  end
end
