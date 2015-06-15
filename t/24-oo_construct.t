## no critic (RCS,VERSION,encapsulation,Module,eval,constant)

use strict;
use warnings;
use Test::More;

use 5.006000;

use Bytes::Random::Secure::Tiny;

# Test the constructor, and its helper functions.

can_ok( 'Bytes::Random::Secure::Tiny', qw/ new / );

$Math::Random::ISAAC::Embedded::EMBEDDED_CSPRNG = 1;
$ENV{'BRST_DEBUG'} = 1;

# Instantiate with a dummy callback so we don't drain entropy.
my $random = new_ok 'Bytes::Random::Secure::Tiny' => [128];

isa_ok $random, 'Bytes::Random::Secure::Tiny';
is $random->{'bits'}, 128, 'Seed is 128 bits.';

done_testing();
