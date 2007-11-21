use inc::Module::Install;

name 'Catalyst-Plugin-Session-HMAC';
all_from 'lib/Catalyst/Plugin/Session/HMAC.pm';

requires 'Crypt::Util' => '0.05';
requires 'Class::C3';

build_requires 'URI::Escape';
build_requires 'Catalyst::Runtime';
build_requires 'Test::WWW::Mechanize::Catalyst';
build_requires 'Test::More';
build_requires 'ok';

WriteAll();
