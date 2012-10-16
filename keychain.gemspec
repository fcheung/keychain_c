Gem::Specification.new do |s|
  s.name = %q{keychain}
  s.version = "0.1.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Frederick Cheung"]
  s.date = %q{2012-10-16}
  s.description = %q{Ruby wrapper for OS X's keychain }
  s.email = %q{frederick.cheung@gmail.com}
  s.extensions = ["ext/extconf.rb"]
  s.files += Dir["ext/*.h"]
  s.files += Dir["ext/*.c"]
  s.files += Dir["lib/*.rb"]
  s.files += Dir["spec/**/*"]
  
  s.license = 'MIT'
  s.has_rdoc = false
  s.homepage = %q{http://github.com/fcheung/rkeychain}
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.8.10}
  s.summary = %q{Ruby wrapper for  OS X's keychain}  
  s.required_ruby_version = '>= 1.9.2'
end

