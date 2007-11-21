#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 19;
use URI::Escape;

# setup library path
use FindBin qw($Bin);
use lib "$Bin/lib";

# make sure testapp works
use ok 'TestApp';

# a live test against TestApp, the test application
use Test::WWW::Mechanize::Catalyst 'TestApp';
my $mech = Test::WWW::Mechanize::Catalyst->new;
$mech->get_ok('http://localhost/', 'get main page');
$mech->content_like(qr/it works/i, 'see if it has our text');

my $orig_expires;
$mech->cookie_jar->scan( 
    sub { 
        $orig_expires = TestApp->
          _thaw_session_string(uri_unescape($_[2]))->{__expires};
    }
);

ok $orig_expires, 'got expiry from cryptocookie OF DEATH';

for(1..3){
    $mech->get_ok('http://localhost/increment');
    $mech->content_like(qr/count is now $_/);
}

diag "Testing expiration; this might fail if your machine is too loaded.";
$mech->get_ok('http://localhost/expire_counter');
$mech->get_ok('http://localhost/increment');
$mech->content_like(qr/count is now 4/);
sleep 6;
$mech->get_ok('http://localhost/increment');
$mech->content_like(qr/count is now 1/);
$mech->get_ok('http://localhost/get_non_expired_key');
$mech->content_like(qr/bar/);

my $new_expires;
$mech->cookie_jar->scan( 
    sub { 
        $new_expires = TestApp->
          _thaw_session_string(uri_unescape($_[2]))->{__expires};
    }
);

ok $new_expires, 'got new expiry';
ok $new_expires > $orig_expires, 'expiry moved forward with time';
