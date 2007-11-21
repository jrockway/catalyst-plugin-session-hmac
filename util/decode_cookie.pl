#!/usr/bin/env perl

use strict;
use warnings;
use YAML;
use Crypt::Util;
use URI::Escape;

my $key    = shift @ARGV;
my $cookie = shift @ARGV;
my $util = Crypt::Util->new;
print Dump(
    $util->thaw_tamper_proof(
        $util->decode_string_printable(uri_unescape($cookie)),
        key => $key,
    )
). "\n";
