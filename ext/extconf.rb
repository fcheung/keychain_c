require 'mkmf'
$CFLAGS << ' -framework Security'
create_makefile('keychain')
