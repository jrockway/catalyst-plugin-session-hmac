use inc::Module::Install;

name 'Catalyst-Plugin-Session-Store-Cookie';
all_from 'lib/Catalyst/Plugin/Session/Store/Cookie.pm';

requires 'Crypt::Util' => '0.05';
requires 'Class::C3';

build_requires 'URI::Escape';
build_requires 'Catalyst::Runtime';
build_requires 'Test::WWW::Mechanize::Catalyst';
build_requires 'Test::More';
build_requires 'ok';

WriteAll();
