package TestApp::Controller::Root;
use strict;
use warnings;

__PACKAGE__->config(namespace => q{});

use base 'Catalyst::Controller';

# your actions replace this one
sub main :Path { $_[1]->res->body('<h1>It works</h1>') }

sub increment :Local {
    my ($self, $c) = @_;
    my $count = ++$c->session->{counter};
    
    $c->res->body("count is now $count");
}

sub session :Local {
    my ($self, $c) = @_;
    use YAML;
    $c->res->body(YAML::Dump($c->session));
}

sub expire_counter :Local {
    my ($self, $c) = @_;
    $c->session->{foo} = 'bar';
    $c->session_expire_key( counter => 5 );
    $c->res->body('expire in 5 seconds');
}

sub get_non_expired_key :Local {
    my ($self, $c) = @_;
    $c->res->body($c->session->{foo});
}

sub request_count :Local {
    my ($self, $c) = @_;
    $c->res->body($c->session->{request_count});
}

1;
