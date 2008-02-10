package TestApp;
use strict;
use warnings;

use Catalyst qw(Session::HMAC Session::HMAC::Compat);

__PACKAGE__->config->{session}{key} = 'foobar';
__PACKAGE__->setup;

1;
