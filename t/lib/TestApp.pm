package TestApp;
use strict;
use warnings;

use Catalyst qw(Session::Store::Cookie);

__PACKAGE__->config->{session}{key} = 'foobar';
__PACKAGE__->setup;

1;
