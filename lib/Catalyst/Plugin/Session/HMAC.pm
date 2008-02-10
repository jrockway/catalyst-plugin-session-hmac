package Catalyst::Plugin::Session::HMAC;
use strict;
use warnings;
use Crypt::Util;
use Class::C3;

our $VERSION = '0.00_01';

my $serial_number = 0; # XXX: this is BADBAD.

# public API

## session

sub hmac_session_id {
    shift->hmac_session->{serial};
}

sub hmac_session_expires {
    my ($c) = @_;
    return $c->_calculate_hmac_session_expiry;
}

sub hmac_delete_session {
    $_[0]->_prepare_empty_hmac_session;
    return;
}

sub hmac_delete_session_reason {
    return 'not implemented';
}

sub hmac_session_expire_key { # this is not auto-extended like everything else
    my ( $c, %keys ) = @_;
    
    my $now = time;
    @{ $c->hmac_session->{$c->_hmac_session_expire_keys_key_name} }{ keys %keys } =
      map { $now + $_ } values %keys;
}

sub hmac_session {
    my $c = shift;
    die 'It is too early/late to call $c->hmac_session' if !$c->{hmac_session};
    return $c->{hmac_session};
}

## flash

sub hmac_flash {
    my $c = shift;

    # on the first hit, note the keys for deletion
    $c->{hmac_session}{$c->_hmac_flash_keep_key_name} = {%{$c->{hmac_session}{flash}}}
      if !$c->{hmac_session}{$c->_hmac_flash_keep_key_name};
    return $c->{hmac_session}{flash};
}

sub hmac_clear_flash {
    my $c = shift;
    $c->{hmac_session}{flash} = {};
    return;
}

sub hmac_keep_flash {
    my ($c, @keys) = @_;
    $c->{hmac_session}{$c->_hmac_flash_keep_key_name}{$_} = undef for @keys;
    return;
}

# hook into catalyst

sub setup {
    my $app = shift;
    
    die 'you must specify a cryptography key as $app->config->{hmac_session}{key}'
      unless $app->_hmac_session_config->{key};
    
    # default timeout (0 means never)
    $app->_hmac_session_config->{expires} = 3600 
      unless defined $app->_hmac_session_config->{expires};
    
    return $app->next::method(@_);
}

sub prepare_action {
    my $c = shift;

    # move flash to stash    
    if($c->_hmac_session_config->{flash_to_stash}){
        my $flash_data = $c->hmac_flash; # this counts as a read
        @{ $c->stash }{ keys %$flash_data } = values %$flash_data;
    }
    
    return $c->next::method(@_);
}

sub prepare_cookies {
    my $c = shift;
    $c->next::method(@_);
    $c->prepare_hmac_session;
    return;
}

sub finalize_cookies {
    my $c = shift;
    $c->finalize_hmac_session;
    $c->next::method(@_);
    return;
}

# our hooks for other people

sub prepare_hmac_session {
    my $c = shift;

    eval {
        # get crypted hmac_session data
        my $cookie = $c->req->cookies->{$c->_hmac_session_cookie_key_name};
        die 'No hmac_session cookie' if !$cookie;
        
        # thaw
        my $hmac_session = eval { $c->_thaw_hmac_session_string($cookie->{value}) };
        die q{Invalid hmac_session cookie received from '}. 
          $c->req->address. qq{' ($@)}
            if !$hmac_session;
        
        # check address
        die q{Address mismatch; was }. $hmac_session->{__address}. 
            q{ now is }. $c->req->address
              if $c->_hmac_session_config->{check_addresss} && 
                 $hmac_session->{$c->_hmac_session_address_key_name} && 
                 $hmac_session->{$c->_hmac_session_address_key_name} ne $c->req->address;
        
        # if thawed hmac_session is not expired, or has no expiry; use it
        die q{'}. $c->req->address. q{' sent an expired hmac_session}
          unless !$hmac_session->{$c->_hmac_session_expiry_key_name} || 
            $hmac_session->{$c->_hmac_session_expiry_key_name} - time() > 0 ;

        # you made it this far! 50 GP
        $c->_prepare_valid_hmac_session($hmac_session);
    };
    
    if(my $error = $@){
        $error =~ s/at .+?$//;
        $c->log->warn($error) unless $error =~ /No hmac_session cookie/;
        $c->_prepare_empty_hmac_session;
    }
    
    return;
}

sub finalize_hmac_session {
    my $c = shift;

    # calc expires
    my $perl_expires   = $c->_calculate_hmac_session_expiry;
    my $cookie_expires = $c->_calculate_hmac_session_cookie_expiry;

    # munge hmac_session
    my $hmac_session_hash = delete $c->{hmac_session};
    $hmac_session_hash->{$c->_hmac_session_expiry_key_name} = $perl_expires;
    $hmac_session_hash->{$c->_hmac_session_address_key_name} = $c->req->address;
    
    # delete unchanged flash keys if we used the flash this request
    #use YAML; warn Dump($hmac_session_hash);
    foreach my $key (%{$hmac_session_hash->{$c->_hmac_flash_keep_key_name} || {}}){
        my $value = $hmac_session_hash->{$c->_hmac_flash_keep_key_name}{$key};
        delete $hmac_session_hash->{flash}{$key}
          if defined $value && $hmac_session_hash->{flash}{$key} eq $value;
    }
    delete $hmac_session_hash->{$c->_hmac_flash_keep_key_name};
    
    # serialize it
    my $hmac_session = $c->_freeze_hmac_session_hash($hmac_session_hash);
    
    # set it up as a cookie
    # TODO split big hmac_sessions
    $c->res->cookies->{$c->_hmac_session_cookie_key_name} = {
        %{$c->_hmac_session_cookie_extra_opts},
        value   => $hmac_session,
        expires => $cookie_expires,
    };

    # this never returns anything
    return;
}

sub _hmac_session_config {    
    my $app = shift;
    my $session = {};
    if($app->isa('Catalyst::Plugin::Session::HMAC::Compat')){
        # if in compat mode, allow "session"
        $session = $app->config->{session};
    }
    return $app->config->{hmac_session} || $session || {};
}

sub _hmac_session_cookie_key_name {
    return lc(ref $_[0] || $_[0]). '_hmac_session';
}

# not blessing is a blessing in disguise?  no.

sub _hmac_session_expiry_key_name {
    return '__expires';
}

sub _hmac_session_address_key_name {
    return '__address';
}

sub _hmac_flash_keep_key_name {
    return '__keep_flash';
}

sub _hmac_session_expire_keys_key_name {
    return '__expire_keys';
}

# make $c->{hmac_session} hashes

sub _prepare_empty_hmac_session {
    my $c = shift;
    $c->{hmac_session} = { flash => {} };
    return;
}

sub _prepare_valid_hmac_session {
    my ($c, $hmac_session) = @_;

    $c->{hmac_session} = $hmac_session;
    delete $c->{hmac_session}{$c->_hmac_session_expiry_key_name};
    delete $c->{hmac_session}{$c->_hmac_session_address_key_name};
    
    my $now = time;
    my $expire_times = $c->{hmac_session}{$c->_hmac_session_expire_keys_key_name};
    foreach my $key (grep { $expire_times->{$_} < $now } keys %$expire_times){
        delete $c->{hmac_session}{$key};
        delete $expire_times->{$key};
    }

    $c->{hmac_session}{serial} ||= $serial_number++;

    return;
}

sub _hmac_session_cookie_extra_opts {
    my $c = shift;
    return $c->_hmac_session_config->{cookie_extra_opts} || {};
}

sub _hmac_session_expiry_delta {
    return $_[0]->_hmac_session_config->{expires};
}

sub _calculate_hmac_session_cookie_expiry {
    my $c = shift;
    if($c->_hmac_session_expiry_delta){
        return "+". $c->_hmac_session_expiry_delta. "s";
    }
    return;
}

sub _calculate_hmac_session_expiry {
    my $c = shift;
    if($c->_hmac_session_expiry_delta){
        return time + $c->_hmac_session_expiry_delta;
    }
    return; # undef if expires == 0
}

my $util = Crypt::Util->new;

sub _freeze_hmac_session_hash {
    my ($c, $hash) = @_;
    return $util->encode_string_printable(
        $util->tamper_proof(
            $hash || {},
            key => $c->_hmac_session_config->{key},
        )
    );
}

sub _thaw_hmac_session_string {
    my ($c, $string) = @_;
    $string = $string->[0] if ref $string; # XXX: what?
    
    return $util->thaw_tamper_proof(
        $util->decode_string_printable($string),
        key => $c->_hmac_session_config->{key},
    );
}

1;
__END__

=head1 NAME

Catalyst::Plugin::Session::HMAC - store sessions on the user's machine
instead of on the server

=head1 SYNOPSIS

=cut


