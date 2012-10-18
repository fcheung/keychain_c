class Keychain
  class Error < StandardError
    attr_accessor :code
    def initialize(message, code)
      self.code = code
      super message
    end

  end

  def inspect
    "<Keychain 0x#{self.object_id.to_s(16)}: #{path}>"
  end

  def find(first_or_all, attributes={})
    self.class.find(first_or_all, attributes.merge(:keychains => [self]))
  end

end

require 'keychain/keychain'

class Keychain::Item

  Keychain::KEYCHAIN_MAP.each do |ruby_name, attr_name|
    define_method ruby_name do
      @attributes[attr_name]
    end
    define_method ruby_name.to_s+'=' do |value|
      @attributes[attr_name] = value
    end
  end
end
