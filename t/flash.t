#!/usr/bin/env perl

use strict;
use warnings;
use Test::More tests => 6;

# setup library path
use FindBin qw($Bin);
use lib "$Bin/lib";

# a live test against TestApp, the test application
use Test::WWW::Mechanize::Catalyst 'TestApp';
my $mech = Test::WWW::Mechanize::Catalyst->new;

$mech->get_ok('http://localhost/flash/redirect_twice');
$mech->content_like(qr/It worked/);

$mech->get_ok('http://localhost/flash/show_message');
$mech->content_like(qr/No message/);

$mech->get_ok('http://localhost/flash/use_flash');
$mech->content_like(qr/No message/);
