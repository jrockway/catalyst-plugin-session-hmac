package Catalyst::Plugin::Session::HMAC::Compat;
use strict;
use warnings;

# public API
sub sessionid { goto &Catalyst::Plugin::Session::HMAC::hmac_session_id }
sub session_expires { goto &Catalyst::Plugin::Session::HMAC::hmac_session_expires }
sub delete_session { goto &Catalyst::Plugin::Session::HMAC::hmac_delete_session }
sub delete_session_reason { goto &Catalyst::Plugin::Session::HMAC::hmac_delete_session_reason }
sub session_expire_key { goto &Catalyst::Plugin::Session::HMAC::hmac_session_expire_key }
sub session { goto &Catalyst::Plugin::Session::HMAC::hmac_session }
sub flash { goto &Catalyst::Plugin::Session::HMAC::hmac_flash }
sub clear_flash { goto &Catalyst::Plugin::Session::HMAC::hmac_clear_flash }
sub keep_flash { goto &Catalyst::Plugin::Session::HMAC::hmac_keep_flash }

# catalyst hooks
sub prepare_session { goto &Catalyst::Plugin::Session::HMAC::prepare_hmac_session }
sub finalize_session { goto &Catalyst::Plugin::Session::HMAC::finalize_hmac_session }

# methods for compat that do nothing.
sub calculate_extended_session_expires {}
sub calculate_initial_session_expires {}
sub create_session_id_if_needed {}
sub delete_session_id {}
sub extend_session_expires {}
sub extend_session_id {}
sub get_session_id { $_[0]->sessionid }
sub reset_session_expires {}
sub session_is_valid { 1 }
sub set_session_id {}

BEGIN {
    package Catalyst::Plugin::Session;
    1;
}

our @ISA = qw(Catalyst::Plugin::Session); # dumbass auth plugins check this

1;
__END__

=head1 NAME

Catalyst::Plugin::Session::HMAC::Compat - use C<Session::HMAC> as a drop-in
replacement for the usual C<Catalyst::Plugin::Session>.

=head1 SYNOPSIS

=cut
