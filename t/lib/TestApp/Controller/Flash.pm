package TestApp::Controller::Flash;
use strict;
use warnings;

use base 'Catalyst::Controller';

sub redirect_twice :Local {
    my ($self, $c) = @_;
    $c->flash->{message} = 'It worked';
    $c->res->redirect($c->uri_for('/flash/redirect1'));
    $c->res->body('fail');
}

sub redirect1 :Local {
    my ($self, $c) = @_;
    $c->res->redirect($c->uri_for('/flash/show_message'));
    $c->res->body('fail');
}

sub show_message :Local {
    my ($self, $c) = @_;
    $c->res->body($c->flash->{message} || 'No message');
}

sub use_flash :Local {
    my ($self, $c) = @_;
    $c->flash->{foo} = 'bar';
    $c->flash->{message} = 'FAIL';
    $c->res->redirect($c->uri_for('/flash/redirect2'));
    $c->res->body('fail');
}

sub redirect2 :Local {
    my ($self, $c) = @_;
    my $foo = $c->flash->{foo}; # read the flash
    $c->res->redirect($c->uri_for('/flash/show_message'));
    $c->res->body('fail');
}

1;
