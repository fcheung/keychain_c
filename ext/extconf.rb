require 'mkmf'
$CFLAGS << ' -std=c99'
$DLDFLAGS << ' -framework Security -framework CoreFoundation'
create_makefile('keychain', 'ext')
