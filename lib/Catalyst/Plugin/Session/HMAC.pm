package Catalyst::Plugin::Session::HMAC;
use strict;
use warnings;
use Crypt::Util;
use Class::C3;

our $VERSION = '0.00_01';

# public API

## session

sub sessionid { die 'there is no such thing for HMAC sessions' }

sub session_expires {
    my ($c) = @_;
    return $c->_calculate_session_expiry;
}

sub delete_session {
    $_[0]->_prepare_empty_session;
    return;
}

sub delete_session_reason {
    return 'not implemented';
}

sub session_expire_key { # this is not auto-extended like everything else
    my ( $c, %keys ) = @_;
    
    my $now = time;
    @{ $c->session->{$c->_session_expire_keys_key_name} }{ keys %keys } =
      map { $now + $_ } values %keys;
}

sub session {
    my $c = shift;
    die "It is too early/late to call $c->session" if !$c->{session};
    return $c->{session};
}

## flash

sub flash {
    my $c = shift;

    # on the first hit, note the keys for deletion
    $c->{session}{$c->_flash_keep_key_name} = {%{$c->{session}{flash}}}
      if !$c->{session}{$c->_flash_keep_key_name};
    return $c->{session}{flash};
}

sub clear_flash {
    my $c = shift;
    $c->{session}{flash} = {};
    return;
}

sub keep_flash {
    my ($c, @keys) = @_;
    $c->{session}{$c->_flash_keep_key_name}{$_} = undef for @keys;
    return;
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

sub prepare_action {
    my $c = shift;

    # move flash to stash    
    my $flash_data = $c->{session}{flash};
    @{ $c->stash }{ keys %$flash_data } = values %$flash_data
      if $c->_session_config->{flash_to_stash} && $flash_data;
    
    return $c->next::method(@_);
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

sub prepare_session {
    my $c = shift;

    eval {
        # get crypted session data
        my $cookie = $c->req->cookies->{$c->_session_cookie_key_name};
        die 'No session cookie' if !$cookie;
        
        # thaw
        my $session = eval { $c->_thaw_session_string($cookie->{value}) };
        die q{Invalid session cookie received from '}. 
          $c->req->address. qq{' ($@)}
            if !$session;
        
        # check address
        die q{Address mismatch; was }. $session->{__address}. 
            q{ now is }. $c->req->address
              if $c->_session_config->{check_addresss} && 
                 $session->{$c->_session_address_key_name} && 
                 $session->{$c->_session_address_key_name} ne $c->req->address;
        
        # if thawed session is not expired, or has no expiry; use it
        die q{'}. $c->req->address. q{' sent an expired session}
          unless !$session->{$c->_session_expiry_key_name} || 
            $session->{$c->_session_expiry_key_name} - time() > 0 ;

        # you made it this far! 50 GP
        $c->_prepare_valid_session($session);
    };
    
    if(my $error = $@){
        $error =~ s/at .+?$//;
        $c->log->warn($error) unless $error =~ /No session cookie/;
        $c->_prepare_empty_session;
    }
    
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
    $session_hash->{$c->_session_address_key_name} = $c->req->address;
    
    # delete unchanged flash keys if we used the flash this request
    #use YAML; warn Dump($session_hash);
    foreach my $key (%{$session_hash->{$c->_flash_keep_key_name} || {}}){
        my $value = $session_hash->{$c->_flash_keep_key_name}{$key};
        delete $session_hash->{flash}{$key}
          if defined $value && $session_hash->{flash}{$key} eq $value;
    }
    delete $session_hash->{$c->_flash_keep_key_name};
    
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

# not blessing is a blessing in disguise?  no.

sub _session_expiry_key_name {
    return '__expires';
}

sub _session_address_key_name {
    return '__address';
}

sub _flash_keep_key_name {
    return '__keep_flash';
}

sub _session_expire_keys_key_name {
    return '__expire_keys';
}

# make $c->{session} hashes

sub _prepare_empty_session {
    my $c = shift;
    $c->{session} = { flash => {} };
    return;
}

sub _prepare_valid_session {
    my ($c, $session) = @_;

    $c->{session} = $session;
    delete $c->{session}{$c->_session_expiry_key_name};
    delete $c->{session}{$c->_session_address_key_name};
    
    my $now = time;
    my $expire_times = $c->{session}{$c->_session_expire_keys_key_name};
    foreach my $key (grep { $expire_times->{$_} < $now } keys %$expire_times){
        delete $c->{session}{$key};
        delete $expire_times->{$key};
    }
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

my $util = Crypt::Util->new;

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

