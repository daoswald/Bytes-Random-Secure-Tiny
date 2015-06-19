#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;

use Bytes::Random::Secure::Tiny;
$Math::Random::ISAAC::Embedded::EMBEDDED_CSPRNG = 1;

ok !defined Crypt::Random::Seed::Embedded::__read_file('/dev/urandom/',0),
    'CRSE::__read_file returns undef for requests of zero bytes.';


done_testing();
