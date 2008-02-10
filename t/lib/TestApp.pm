package TestApp;
use strict;
use warnings;
use Class::C3;

use Catalyst qw(Session::HMAC Session::HMAC::Compat);

__PACKAGE__->config->{session}{key} = 'foobar';
__PACKAGE__->setup;

sub prepare_session {
    my $c = shift;
    $c->next::method(@_);
    $c->session->{request_count}++;
}

1;
