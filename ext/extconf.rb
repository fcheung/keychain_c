require 'mkmf'
#$CFLAGS << ' -framework Security -framework CoreFoundation'
$DLDFLAGS << ' -framework Security -framework CoreFoundation'
create_makefile('keychain')
