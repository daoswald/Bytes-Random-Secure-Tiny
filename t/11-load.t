## no critic (RCS,VERSION,encapsulation,Module)

use strict;
use warnings;

use Test::More tests => 1;


BEGIN {
    use_ok( 'Bytes::Random::Secure::Tiny' ) || print "Bail out!\n";
}

diag('Testing Bytes::Random::Secure::Tiny ' 
  . "$Bytes::Random::Secure::Tiny::VERSION, Perl $], $^X");

