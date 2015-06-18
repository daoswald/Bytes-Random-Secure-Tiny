use 5.006000;
use strict;
use warnings;
use ExtUtils::MakeMaker;

my %PREREQ_PM = (
);

WriteMakefile(
    NAME          => 'Bytes::Random::Secure::Tiny',
    AUTHOR        => q{David Oswald <davido@cpan.org>},
    VERSION_FROM  => 'lib/Bytes/Random/Secure/Tiny.pm',
    ABSTRACT_FROM => 'lib/Bytes/Random/Secure/Tiny.pm',
    ( $ExtUtils::MakeMaker::VERSION >= 6.3002
        ? ( 'LICENSE' => 'perl' )
        : () ),
    PL_FILES  => {},
    CONFIGURE_REQUIRES => {
      'ExtUtils::MakeMaker' => '6.56',
    },
    BUILD_REQUIRES => {
      'Test::More'    => '0.98',    # A recent version is needed.
    },
    MIN_PERL_VERSION => '5.008000',
    PREREQ_PM => \%PREREQ_PM,
    META_MERGE => {
      'resources' => {
        'meta-spec' => { version => 2 }, 
        'repository'  => {
          'url'   => 'git://github.com/daoswald/Bytes-Random-Secure-Tiny.git',
          'web'   => 'http://github.com/daoswald/Bytes-Random-Secure-Tiny',
          'type'  => 'git',
        },
      },
    },
    dist      => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean     => { FILES => 'Bytes-Random-Secure-Tiny-*',       },
);
