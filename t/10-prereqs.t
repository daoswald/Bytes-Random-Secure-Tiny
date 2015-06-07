## no critic (RCS,VERSION,encapsulation,Module)
use strict;
use warnings;

use Test::More;

BEGIN {
    use_ok('Math::Random::ISAAC');
    use_ok('Crypt::Random::Seed');
}

done_testing();
