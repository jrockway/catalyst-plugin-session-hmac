package Catalyst::Plugin::Session::HMAC;
use strict;
use warnings;
use Crypt::Util;
use Class::C3;
my $util = Crypt::Util->new;

our $VERSION = '0.01';

# public API

sub session {
    my $c = shift;
    die "It is too early/late to call $c->session" if !$c->{session};
    return $c->{session};
}

sub flash {
    my $c = shift;
    return $c->{session}{flash};
}

# hook into catalyst

sub setup {
    my $app = shift;
    die "you must specify a cryptography key as $app->_session_config->{key}"
      unless $app->config;

    # default timeout (0 means never)
    $app->_session_config->{expires} = 3600 
      unless defined $app->_session_config->{expires};
    
    return $app->next::method(@_);
}

sub prepare_cookies {
    my $c = shift;
    $c->next::method(@_);
    $c->prepare_session;
    return;
}

sub finalize_cookies {
    my $c = shift;
    $c->finalize_session;
    $c->next::method(@_);
    return;
}

# our hooks for other people

sub prepare_session { # XXX: too many returns!
    my $c = shift;

    # get crypted session data
    my $cookie = $c->req->cookies->{$c->_session_cookie_key_name};
    if(!$cookie){
        $c->_prepare_empty_session;
        return;
    }

    # thaw
    my $session = eval { $c->_thaw_session_string($cookie->{value}) };
    if(!$session){
        # session was invalid (sig didn't validate)
        $c->log->warn(
            q{Invalid session cookie received from '}. 
              $c->req->hostname.
                qq{' ($@)}
        );
        $c->_prepare_empty_session;
        return;
    }

    # if thawed session is not expired, or has no expiry; use it
    if(!$session->{$c->_session_expiry_key_name} || $session->{$c->_session_expiry_key_name} - time() > 0){
        $c->{session} = $session;
        delete $c->{session}{$c->_session_expiry_key_name}; # none of the user's business
        return;
    }
    
    # expired session, kill it
    $c->log->debug(q{'}. $c->req->hostname. q{' sent an expired session})
      if $c->log->is_debug;
    
    $c->_prepare_empty_session;
    return;
}

sub finalize_session {
    my $c = shift;

    # calc expires
    my $perl_expires   = $c->_calculate_session_expiry;
    my $cookie_expires = $c->_calculate_session_cookie_expiry;

    # munge session
    my $session_hash = delete $c->{session};
    $session_hash->{$c->_session_expiry_key_name} = $perl_expires;
    
    # serialize it
    my $session = $c->_freeze_session_hash($session_hash);
    
    # set it up as a cookie
    # TODO split big sessions
    $c->res->cookies->{$c->_session_cookie_key_name} = {
        %{$c->_session_cookie_extra_opts},
        value   => $session,
        expires => $cookie_expires,
    };

    # this never returns anything
    return;
}

sub _session_config {
    return $_[0]->config->{session} || {};
}

sub _session_cookie_key_name {
    return lc(ref $_[0] || $_[0]). '_session';
}

sub _session_expiry_key_name {
    return '__expires';
}

sub _prepare_empty_session {
    my $c = shift;
    $c->{session} = { flash => {} };
    return;
}

sub _session_cookie_extra_opts {
    my $c = shift;
    return $c->_session_config->{cookie_extra_opts} || {};
}

sub _session_expiry_delta {
    return $_[0]->_session_config->{expires};
}

sub _calculate_session_cookie_expiry {
    my $c = shift;
    if($c->_session_expiry_delta){
        return "+". $c->_session_expiry_delta. "s";
    }
    return;
}

sub _calculate_session_expiry {
    my $c = shift;
    if($c->_session_expiry_delta){
        return time + $c->_session_expiry_delta;
    }
    return; # undef if expires == 0
}

sub _freeze_session_hash {
    my ($c, $hash) = @_;
    return $util->encode_string_printable(
        $util->tamper_proof(
            $hash || {},
            key => $c->_session_config->{key},
        )
    );
}

sub _thaw_session_string {
    my ($c, $string) = @_;
    $string = $string->[0] if ref $string; # XXX: what?
    
    return $util->thaw_tamper_proof(
        $util->decode_string_printable($string),
        key => $c->_session_config->{key},
    );
}

1;
__END__

=head1 NAME

Catalyst::Plugin::Session::HMAC - store sessions on the user's machine
instead of on the server

=head1 SYNOPSIS

=cut

