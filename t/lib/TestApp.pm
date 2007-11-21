package TestApp;
use strict;
use warnings;

use Catalyst qw(Session::HMAC);

__PACKAGE__->config->{session}{key} = 'foobar';
__PACKAGE__->setup;

1;
