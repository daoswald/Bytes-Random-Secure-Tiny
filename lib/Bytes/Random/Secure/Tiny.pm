# --------------------------------------------------------- #
# Crypt::Random::Seed::Embedded, taken with consent from    #
# Crypt::Random::Seed, by Dana Jacobson.                    #
# --------------------------------------------------------- #

package Crypt::Random::Seed::Embedded;
use strict;
use warnings;
use Fcntl;
use Carp qw/carp croak/;

# cert insists on using constant, but regular critic doesn't like it.
## no critic (constant)

our $VERSION = '0.03';
use constant UINT32_SIZE => 4;

sub new {
    my ($class, %params) = @_;
    my $self = {};

    # This is a sorted list -- the first one that returns true gets used.
    my @methodlist
        = ( \&_try_win32, \&_try_egd, \&_try_dev_random, \&_try_dev_urandom );

    foreach my $m (@methodlist) {
        my ($name, $rsub, $isblocking, $isstrong) = $m->();
        next unless defined $name;
        next if $isblocking
            &&  grep { $_ } @params{qw( NonBlocking Nonblocking nonblocking )};
        @{$self}{qw( Name    SourceSub  Blocking      Strong    )}
                 = ( $name,  $rsub,     $isblocking,  $isstrong );
        last;
    }

    # Couldn't find anything appropriate
    return unless defined $self->{SourceSub};
    return bless $self, $class;
}

sub random_values {
    my ($self, $nvalues) = @_;
    return unless defined $nvalues && int($nvalues) > 0;
    my $rsub = $self->{SourceSub};
    return unless defined $rsub;
    return unpack( 'L*', $rsub->(UINT32_SIZE * int($nvalues)) );
}

sub _try_dev_urandom {
    return unless -r "/dev/urandom";
    return ('/dev/urandom', sub { __read_file('/dev/urandom', @_); }, 0, 0);
}

sub _try_dev_random {
    return unless -r "/dev/random";
    # FreeBSD's /dev/random is 256-bit Yarrow non-blocking.
    # Is it 'strong'?  Debatable -- we'll say it is.
    my $blocking = ($^O eq 'freebsd') ? 0 : 1;
    return ('/dev/random', sub { __read_file('/dev/random', @_); },
            $blocking, 1);
}

sub __read_file {
    my ($file, $nbytes) = @_;
    return unless defined $nbytes && $nbytes > 0;
    sysopen(my $fh, $file, O_RDONLY);
    binmode $fh;
    my($s, $buffer, $nread) = ('', '', 0);
    while ($nread < $nbytes) {
        my $thisread = sysread $fh, $buffer, $nbytes-$nread;
        # Count EOF as an error.
        croak "Error reading $file: $!\n"
            unless defined $thisread && $thisread > 0;
        $s .= $buffer;
        $nread += length($buffer);
    }
    croak "Internal file read error: wanted $nbytes, read $nread"
        unless $nbytes == length($s);  # assert
    return $s;
}

sub _try_win32 {
    return unless $^O eq 'MSWin32';
    # Cygwin has /dev/random at least as far back as 2000.
    eval { require Win32; require Win32::API; require Win32::API::Type; 1; }
        or return;

    use constant CRYPT_SILENT      => 0x40;       # Never display a UI.
    use constant PROV_RSA_FULL     => 1;          # Which service provider.
    use constant VERIFY_CONTEXT    => 0xF0000000; # Don't need existing keepairs
    use constant W2K_MAJOR_VERSION => 5;          # Windows 2000
    use constant W2K_MINOR_VERSION => 0;

    my ($major, $minor) = (Win32::GetOSVersion())[1, 2];
    return if $major < W2K_MAJOR_VERSION;

    if ($major == W2K_MAJOR_VERSION && $minor == W2K_MINOR_VERSION) {
        # We are Windows 2000.  Use the older CryptGenRandom interface.
        my $crypt_acquire_context_a =
            Win32::API->new('advapi32', 'CryptAcquireContextA', 'PPPNN','I');
        return unless defined $crypt_acquire_context_a;
        my $context = chr(0) x Win32::API::Type->sizeof('PULONG');
        my $result = $crypt_acquire_context_a->Call(
             $context, 0, 0, PROV_RSA_FULL, CRYPT_SILENT | VERIFY_CONTEXT );
        return unless $result;
        my $pack_type = Win32::API::Type::packing('PULONG');
        $context = unpack $pack_type, $context;
        my $crypt_gen_random =
            Win32::API->new( 'advapi32', 'CryptGenRandom', 'NNP', 'I' );
        return unless defined $crypt_gen_random;
        return ('CryptGenRandom',
            sub {
                my $nbytes = shift;
                my $buffer = chr(0) x $nbytes;
                my $result = $crypt_gen_random->Call($context, $nbytes, $buffer);
                croak "CryptGenRandom failed: $^E" unless $result;
                return $buffer;
            }, 0, 1);  # Assume non-blocking and strong
    } else {
        my $rtlgenrand = Win32::API->new( 'advapi32', <<'_RTLGENRANDOM_PROTO_');
INT SystemFunction036(
  PVOID RandomBuffer,
  ULONG RandomBufferLength
)
_RTLGENRANDOM_PROTO_
        return unless defined $rtlgenrand;
        return ('RtlGenRand',
            sub {
                my $nbytes = shift;
                my $buffer = chr(0) x $nbytes;
                my $result = $rtlgenrand->Call($buffer, $nbytes);
                croak "RtlGenRand failed: $^E" unless $result;
                return $buffer;
            }, 0, 1);  # Assume non-blocking and strong
    }
    return;
}

sub _try_egd {
    # For locations, we'll look in the files OpenSSL's RAND_egd looks, as well
    # as /etc/entropy which egd 0.9 recommends.  This also works with PRNGD.
    # PRNGD uses a seed+CSPRNG so is non-blocking, but we can't tell them apart.
    my @devices
        = qw(/var/run/egd-pool /dev/egd-pool /etc/egd-pool /etc/entropy);
    foreach my $device (@devices) {
        next unless -r $device && -S $device;
        eval { require IO::Socket; 1; } or return;
        # We're looking for a socket that returns entropy available when given
        # that command. Set timeout to 1 to prevent hanging -- if it is a socket
        # but won't return the available entropy in under a second, move on.
        my $socket = IO::Socket::UNIX->new(Peer => $device, Timeout => 1);
        next unless $socket;
        $socket->syswrite( pack("C", 0x00), 1) or next;
        die if $socket->error;
        my($entropy_string, $nread);
        # Sadly this doesn't honor the timeout. We'll have to do an eval/alarm.
        # We only timeout here if this is a live socket to a sleeping process.
        eval {
            local $SIG{ALRM} = sub { die "alarm\n" };
            alarm 1;
            $nread = $socket->sysread($entropy_string, 4);
            alarm 0;
        };
        if ($@) {
            die unless $@ eq "alarm\n";
            next;
        }
        next unless defined $nread && $nread == 4;
        my $entropy_avail = unpack("N", $entropy_string);
        return ('EGD', sub { __read_egd($device, @_); }, 1, 1);
    }
    return;
}

sub __read_egd {
    my ($device, $nbytes) = @_;
    return unless defined $device;
    return unless defined $nbytes && int($nbytes) > 0;
    croak "$device doesn't exist!" unless -r $device && -S $device;
    my $socket = IO::Socket::UNIX->new(Peer => $device);
    croak "Can't talk to EGD on $device. $!" unless $socket;
    my($s, $buffer, $toread) = ('', '', $nbytes);
    while ($toread > 0) {
        my $this_request = ($toread > 255) ? 255 : $toread;
        # Use the blocking interface.
        $socket->syswrite( pack("CC", 0x02, $this_request), 2);
        my $this_grant = $socket->sysread($buffer, $this_request);
        croak "Error reading EDG data from $device: $!\n"
            unless defined $this_grant && $this_grant == $this_request;
        $s .= $buffer;
        $toread -= length($buffer);
    }
    croak "Internal EGD read error: wanted $nbytes, read ", length($s), ""
        unless $nbytes == length($s);  # assert
    return $s;
}

1;

# ------------------------------------------------------------ #
# Math::Random::ISAAC::PP::Embedded: Taken without notice from #
# Math::Random::ISAAC and Math::Random::ISAAC::PP.             #
# ------------------------------------------------------------ #

## no critic (constant,unpack)

package Math::Random::ISAAC::PP::Embedded;

# ABSTRACT: Pure Perl port of the ISAAC PRNG algorithm

use strict;
use warnings;
use Carp ();

our $VERSION = '1.004'; # IE, based on the CPAN version by similar name.

sub new {
    my ($class, @seed) = @_;
    my $seedsize = scalar(@seed);
    my @mm;

    $#mm = $#seed = 255;                # predeclare arrays with 256 slots
    $seed[$_] = 0 for $seedsize .. 255; # Zero-fill unused seed space.

    my $self = {
        randrsl => \@seed,    randcnt => 0,     randmem => \@mm,
        randa   => 0,         randb   => 0,     randc   => 0,
    };

    bless $self, $class;
    $self->_randinit;
    return $self;
}

sub irand {
    my $self = shift;
    # Reset the sequence if we run out of random stuff
    if (!$self->{randcnt}--) {
        _isaac($self);
        $self->{randcnt} = 255;
    }
    return sprintf('%u', $self->{randrsl}->[$self->{randcnt}]);
}

## no critic (ProhibitCStyleForLoops)
## no critic (RequireNumberSeparators)

sub _isaac {
    my $self = shift;
    use integer;

    my $mm = $self->{randmem};
    my $r  = $self->{randrsl};
    # $a and $b are reserved (see 'sort')
    my $aa = $self->{randa};
    my $bb = ($self->{randb} + (++$self->{randc})) & 0xffffffff;
    my ($x, $y); # temporary storage

    # The C code deals with two halves of the randmem separately; we deal with
    # it here in one loop, by adding the &0xff parts. These calls represent the
    # rngstep() macro, but it's inlined here for speed.
    for (my $i = 0; $i < 256; $i += 4) {
        $x = $mm->[$i  ];
        $aa = (($aa ^ ($aa << 13)) + $mm->[($i   + 128) & 0xff]);
        $aa &= 0xffffffff; # Mask out high bits for 64-bit systems
        $mm->[$i  ] = $y = ($mm->[($x >> 2) & 0xff] + $aa + $bb) & 0xffffffff;
        $r->[$i  ] = $bb = ($mm->[($y >> 10) & 0xff] + $x) & 0xffffffff;

        # I don't actually know why the "0x03ffffff" stuff is for. It was in
        # John L. Allen's code. If you can explain this please file a bug report.
        $x = $mm->[$i+1];
        $aa = (($aa ^ (0x03ffffff & ($aa >> 6))) + $mm->[($i+1+128) & 0xff]);
        $aa &= 0xffffffff;
        $mm->[$i+1] = $y = ($mm->[($x >> 2) & 0xff] + $aa + $bb) & 0xffffffff;
        $r->[$i+1] = $bb = ($mm->[($y >> 10) & 0xff] + $x) & 0xffffffff;

        $x = $mm->[$i+2];
        $aa = (($aa ^ ($aa << 2)) + $mm->[($i+2 + 128) & 0xff]);
        $aa &= 0xffffffff;
        $mm->[$i+2] = $y = ($mm->[($x >> 2) & 0xff] + $aa + $bb) & 0xffffffff;
        $r->[$i+2] = $bb = ($mm->[($y >> 10) & 0xff] + $x) & 0xffffffff;

        $x = $mm->[$i+3];
        $aa = (($aa ^ (0x0000ffff & ($aa >> 16))) + $mm->[($i+3 + 128) & 0xff]);
        $aa &= 0xffffffff;
        $mm->[$i+3] = $y = ($mm->[($x >> 2) & 0xff] + $aa + $bb) & 0xffffffff;
        $r->[$i+3] = $bb = ($mm->[($y >> 10) & 0xff] + $x) & 0xffffffff;
    }

    @{$self}{qw/randb randa/} = ($bb,$aa);
    return;
}

sub _randinit {
    my $self = shift;
    use integer;

    # $a and $b are reserved (see 'sort'); $i is the iterator
    my ($c, $d, $e, $f, $g, $h, $j, $k) = (0x9e3779b9)x8; # The golden ratio.
    my $mm = $self->{randmem};
    my $r  = $self->{randrsl};

    for (1..4) {
        $c ^= $d << 11;                     $f += $c;       $d += $e;
        $d ^= 0x3fffffff & ($e >> 2);       $g += $d;       $e += $f;
        $e ^= $f << 8;                      $h += $e;       $f += $g;
        $f ^= 0x0000ffff & ($g >> 16);      $j += $f;       $g += $h;
        $g ^= $h << 10;                     $k += $g;       $h += $j;
        $h ^= 0x0fffffff & ($j >> 4);       $c += $h;       $j += $k;
        $j ^= $k << 8;                      $d += $j;       $k += $c;
        $k ^= 0x007fffff & ($c >> 9);       $e += $k;       $c += $d;
    }

    for (my $i = 0; $i < 256; $i += 8) {
        $c += $r->[$i  ];   $d += $r->[$i+1];
        $e += $r->[$i+2];   $f += $r->[$i+3];
        $g += $r->[$i+4];   $h += $r->[$i+5];
        $j += $r->[$i+6];   $k += $r->[$i+7];

        $c ^= $d << 11;                     $f += $c;       $d += $e;
        $d ^= 0x3fffffff & ($e >> 2);       $g += $d;       $e += $f;
        $e ^= $f << 8;                      $h += $e;       $f += $g;
        $f ^= 0x0000ffff & ($g >> 16);      $j += $f;       $g += $h;
        $g ^= $h << 10;                     $k += $g;       $h += $j;
        $h ^= 0x0fffffff & ($j >> 4);       $c += $h;       $j += $k;
        $j ^= $k << 8;                      $d += $j;       $k += $c;
        $k ^= 0x007fffff & ($c >> 9);       $e += $k;       $c += $d;

        $mm->[$i  ] = $c;   $mm->[$i+1] = $d;
        $mm->[$i+2] = $e;   $mm->[$i+3] = $f;
        $mm->[$i+4] = $g;   $mm->[$i+5] = $h;
        $mm->[$i+6] = $j;   $mm->[$i+7] = $k;
    }

    for (my $i = 0; $i < 256; $i += 8) {
        $c += $mm->[$i  ];  $d += $mm->[$i+1];
        $e += $mm->[$i+2];  $f += $mm->[$i+3];
        $g += $mm->[$i+4];  $h += $mm->[$i+5];
        $j += $mm->[$i+6];  $k += $mm->[$i+7];

        $c ^= $d << 11;                     $f += $c;       $d += $e;
        $d ^= 0x3fffffff & ($e >> 2);       $g += $d;       $e += $f;
        $e ^= $f << 8;                      $h += $e;       $f += $g;
        $f ^= 0x0000ffff & ($g >> 16);      $j += $f;       $g += $h;
        $g ^= $h << 10;                     $k += $g;       $h += $j;
        $h ^= 0x0fffffff & ($j >> 4);       $c += $h;       $j += $k;
        $j ^= $k << 8;                      $d += $j;       $k += $c;
        $k ^= 0x007fffff & ($c >> 9);       $e += $k;       $c += $d;

        $mm->[$i  ] = $c;   $mm->[$i+1] = $d;
        $mm->[$i+2] = $e;   $mm->[$i+3] = $f;
        $mm->[$i+4] = $g;   $mm->[$i+5] = $h;
        $mm->[$i+6] = $j;   $mm->[$i+7] = $k;
    }

    $self->_isaac;
    $self->{randcnt} = 256;
    return;
}

1;

package Math::Random::ISAAC::Embedded;

use strict;
use warnings;
use Carp ();

our $VERSION = '1.004'; # Based on the CPAN version by similar name.

my %CSPRNG = (
    XS  => 'Math::Random::ISAAC::XS',
    PP  => 'Math::Random::ISAAC::PP',
    EM  => 'Math::Random::ISAAC::PP::Embedded',
);

# Wrappers around the actual methods
sub new {
    my ($class, @seed) = @_;

    our $EMBEDDED_CSPRNG =
        defined $EMBEDDED_CSPRNG             ? $EMBEDDED_CSPRNG             :
        defined $ENV{'BRST_EMBEDDED_CSPRNG'} ? $ENV{'BRST_EMBEDDED_CSPRNG'} : 0;

    my $DRIVER =
        $EMBEDDED_CSPRNG                          ? $CSPRNG{'EM'} :
        eval {require Math::Random::ISAAC::XS; 1} ? $CSPRNG{'XS'} :
        eval {require Math::Random::ISAAC::PP; 1} ? $CSPRNG{'PP'} :
                                                    $CSPRNG{'EM'};
    Carp::carp("Using backend $DRIVER\n")
        if $EMBEDDED_CSPRNG && $ENV{'BRST_DEBUG'};

    return bless { '_backend' => $DRIVER->new(@seed) }, $class;
}

sub irand {shift->{_backend}->irand}

1;

package Bytes::Random::Secure::Tiny;

use strict;
use warnings;
use 5.006000;
use Carp;
# use Math::Random::ISAAC::Embeded;
# use Crypt::Random::Seed::Embedded;
use Hash::Util; # We lock internal hash to prevent post-instantiation manip.

our $VERSION = '0.01';

# See Math::Random::ISAAC https://rt.cpan.org/Public/Bug/Display.html?id=64324
use constant SEED_SIZE => 256; # bits; eight 32-bit words.

sub new {
    my($self, $class, $bits) = ({}, @_);
    $bits ||= SEED_SIZE;  # This will be eight 32-bit words.
    die "Number of bits must be 64 <= n <= 8192, and a multipe in 2^n: $bits"
        if $bits < 64 || $bits > 8192 || !_ispowerof2($bits);
    return Hash::Util::lock_hashref bless {
        bits => $bits,
        _rng => Math::Random::ISAAC::Embedded->new(do{
            my $source = Crypt::Random::Seed::Embedded->new(NonBlocking=>1)
                || die 'Could not get a seed source.';
            $source->random_values($bits/32);
        }),
    }, $class;
}

sub _ispowerof2 {my $n = shift; return ($n >= 0) && (($n & ($n-1)) ==0 )}
sub irand {shift->{'_rng'}->irand} # public API, and consumed internally.
sub bytes_hex {unpack 'H*', shift->bytes(shift)} # lc Hex digits only, no '0x'

sub bytes {
      my($self, $bytes) = @_;
    $bytes  = defined $bytes ? int abs $bytes : 0; # Default 0, coerce to UINT.
    my $str = q{};
    while ($bytes >= 4) {                  # Utilize irand()'s 32 bits.
        $str .= pack("L", $self->irand);
        $bytes -= 4;
    }
    if ($bytes > 0) { # Handle 16b and 8b respectively.
        $str .= pack("S", ($self->irand >> 8) & 0xFFFF) if $bytes >= 2;
        $str .= pack("C", $self->irand & 0xFF) if $bytes % 2;
    }
    return $str;
}

sub string_from {
    my($self, $bag, $bytes) = @_;
    $bag           = defined $bag ? $bag : q{};
    $bytes         = defined $bytes ? int abs $bytes : 0;
    my $range      = length $bag;
    croak 'Bag size must be at least one character.' unless $range;
    my $rand_bytes = q{}; # We need an empty, defined string.
    $rand_bytes  .= substr $bag, $_, 1 for $self->_ranged_randoms($range, $bytes);
    return $rand_bytes;
}

sub _ranged_randoms {
    my ($self, $range, $count) = @_;
    $_ = defined $_ ? $_ : 0 for $count, $range;
    croak "$range exceeds irand max limit of 2^^32." if $range > 2**32;

    # Find nearest factor of 2**32 >= $range.
    my $divisor = do {
        my ($n, $d) = (0,0);
        while ($n <= 32 && $d < $range) {$d = 2 ** $n++}
        $d;
    };

    my @randoms;
    $#randoms = $count-1; @randoms = (); # Microoptimize: Preextend & purge.

    for my $n (1 .. $count) { # re-roll if r-num is out of bag range (modbias)
        my $rand = $self->irand % $divisor;
        $rand    = $self->irand % $divisor while $rand >= $range;
        push @randoms, $rand;
    }
    return @randoms;
}

1;

=pod

=head1 NAME

Bytes::Random::Secure::Tiny - A tiny Perl extension to generate
cryptographically-secure random bytes.

=head1 SYNOPSIS

    use Bytes::Random::Secure::Tiny;

    my $rng = Bytes::Random::Secure->new; # Seed with 512 bits.

    my $bytes  = $rng->bytes(32);        # A string of 32 random bytes.
    my $long   = $rng->irand;            # 32-bit random integer.
    my $hex    = $rng->hex_digits(10);   # Ten hex digits.
    my $string = $rng->string_from('abc', 10); Random string from a, b, & c.


=head1 DESCRIPTION

L<Bytes::Random::Secure> provides random bytes from a cryptographically
secure random number generator, seeded from strong entropy sources on a wide
variety of platforms.  It is configurable, and has a flexible user interface.

But it has a handful of dependencies.  And its UI may be more complex than
the typical user needs.  L<Bytes::Random::Secure::Tiny> is designed to provide
what 90% of Bytes::Random::Secure's users need, but with a simpler user
interface, no configuration, and in a single module with no dependencies
beyond core Perl.

In many cases this module may be a drop-in replacement for
L<Bytes::Random::Secure>. This module uses a cryptographic quality random
number generator that uses the ISAAC algorithm, adapted from
L<Math::Random::ISAAC>, and should be suitable for cryptographic purposes.
The harder problem to solve is how to seed the generator.  This module uses
an approach adapted from L<Crypt::Random::Seed> to generate the initial
seeds for the ISAAC CSPRNG.

=head1 RATIONALE

There are many uses for cryptographic quality randomness. This module aims to
provide a generalized tool that can fit into many applications while providing
a zero dependency chain, and a user interface that is both minimal and simple.
You're free to come up with your own use-cases, but there are several
obvious ones:

=over 4

=item * Creating temporary passphrases using the C<string_from> method.

=item * Generating per-account random salt to be hashed along with passphrases 
to prevent rainbow table attacks.

=item * Generating a secret that can be hashed along with a cookie's session
content to prevent cookie forgeries.

=item * Building raw cryptographic-quality pseudo-random data sets for testing
or sampling.

=item * Feeding secure key-gen utilities.

=back

Why use this module?  This module employs several well-designed algorithms
adapted from established CPAN tools to generate a strong random seed, and then
to instantiate a high quality cryptographically secure pseudo-random number
generator based on the seed. It has taken a good deal of research to come up
with what I feel is a strong and sensible choice of established and published
algorithms. The interface is designed with minimalism and simplicity in mind.

As a C<::Tiny> module, the additional goals of no dependencies and a
light-weight code base make this an ideal choice for environments where
heavier dependency chains are avoided.

=head1 EXPORTS

Nothing is exported.

=head1 METHODS

=head2 new

    my $rng = Bytes::Random::Secure::Tiny->new;

Instantiate the pseudo-random number generator object. The seeding of the 
ISAAC CSPRING is lazy; it happens only the first time an accessor is used.
The CSPRNG object should be instantiated as infrequently as practical;
there is no advantage to re-seeding... ever, with the single cavaet that
the CSPRNG object should not be shared by threads or forked processes.

=head2 bytes

    my $random_bytes = $rng->bytes($n);

Returns a string of C<$n> random bytes.  C<$n> should be a positive
integer.

=head2 string_from

    my $random_string = $rng->string_from('abcdefg', 10);

Returns a string of random octets selected from the "Bag" string
(in this case ten octets from 'abcdefg').

=head2 bytes_hex

    my $random_hex = $rng->bytes_hex(12);

Returns a string of hex digits. Remember that each byte is represented by
two hex digits. Therefore, C<<$rng->bytes_hex(1)>> will return a string
of length 2, such as C<7F>.

=head2 irand

    my $unsigned_long = $random->irand;

Returns a pseudo-random 32-bit unsigned integer.  The value will satisfy
C<< 0 <= x <= 2**32-1 >>.

=head1 CONFIGURATION

There is nothing to configure.

=head2 OPTIONAL DEPENDENCY

If performance is a consideration, you may also install 
L<Math::Random::ISAAC::XS>. Bytes::Random::Secure::Tiny will silently
upgrade to use C<Math::Random::ISAAC::XS>, which implements the same
algorithm, but in C and XS for speed.

=head1 CAVEATS

=head2 FORK AND THREAD SAFETY

When programming for parallel computation, create a unique
C<Bytes::Random::Secure::Tiny> object within each process or thread. 
Bytes::Random::Secure::Tiny uses a CSPRNG, and sharing the same RNG between
threads or processes will share the same seed and the same starting point. By
instantiating the B::R::S::T object after forking or creating threads, a
unique randomness stream will be created per thread or process.

=head2 STRONG RANDOMNESS

It's easy to generate weak pseudo-random bytes. It's also easy to think you're
generating strong pseudo-random bytes when really you're not. And it's hard to
test for pseudo-random cryptographic acceptable quality. There are many high
quality random number generators that are suitable for statistical purposes,
but not necessarily up to the rigors of cryptographic use.

Assuring strong (ie, secure) random bytes in a way that works across a wide
variety of platforms is also challenging. A primary goal for this module is to
provide cryptographically secure pseudo-random bytes while still meeting the
secondary goals of simplicity, minimalism, and no dependencies. If more
fine-grained control over seeding methods is needed, use
L<Bytes::Random::Secure> instead.

=head2 ISAAC

The ISAAC algorithm is considered a cryptographically strong pseudo-random
number generator.  It has possible 1.0e2466 initial states. The best known
attack for discovering initial state would theoretically take a complexity of
approximately 4.67e1240, which has no practical impact on ISAAC's security.
Cycles are guaranteed to have a minimum length of 2**40, with an average cycle
of 2**8295. Because there is no practical attack capable of discovering
initial state, and because the average cycle is so long, it's generally
unnecessary to re-seed a running application.  The results are uniformly
distributed, unbiased, and unpredictable unless the seed is known.

To confirm the quality of the CSPRNG, this module's test suite implements the
L<FIPS-140-1|http://csrc.nist.gov/publications/fips/fips1401.htm> tests for
strong random number generators.  See the comments in C<t/27-fips140-1.t> for
details.

=head2 DEPENDENCIES

In order to eliminate all non-core dependencies, this module inlines code
adapted from L<Math::Random::ISAAC> and L<Crypt::Random::Seed>.

The source of cryptographically secure pseudo-random data supplied by this
module comes from the ISAAC algorithm.  The ISAAC CSPRNG is seeded using
algorithms adapted from C<Crypt::Random::Seed>. There are no known weaknesses
in the ISAAC algorithm, and the algorithms adapted from Crypt::Random::Seed
do a very good job of assuring the CSPRNG is well seeded.

This module requires Perl 5.6 or newer. Unicode support in C<string_from> is
best with Perl 5.8.9 or newer. See the INSTALLATION section in this document
for details.

If L<Test::Warn> is installed, test coverage is 100%.  For those who don't want
to bother installing Test::Warn, you can just take our word for it. It's an
optional installation dependency.

=head2 BLOCKING ENTROPY SOURCE

It is possible (and has been seen in testing) that the system's random
entropy source might not have enough entropy in reserve to generate the seed
requested by this module without blocking. In such cases, the blocking will
time out after approximately two seconds, and seeding will fall back to
a strong non-blocking source.

This module seeds as lazily as possible so that using the module, and even
instantiating a Bytes::Random::Secure::Tiny object will not trigger reads from
C</dev/random>. Only the first time the object is used to deliver random bytes
will the RNG be seeded. Long-running scripts may prefer to force early seeding
as close to start-up time as possible, rather than allowing it to happen later
in a program's run-time. This can be achieved simply by invoking any of the
methods that return a random byte. As soon as a random byte is requested for 
the first time, the CSPRNG will be seeded.

=head2 UNICODE SUPPORT

The C<string_from> method permits the user to pass a "bag" (or source)
string containing Unicode characters. For any modern Perl version, this
will work just as you would hope. But some versions of Perl older than
5.8.9 exhibited varying degrees of bugginess in their handling of Unicode.
If you're depending on the Unicode features of this module while using Perl
versions older than 5.8.9 be sure to test thoroughly, and don't be surprised
when the outcome isn't as expected.  ...this is to be expected.  Upgrade.

=head2 MODULO BIAS

Care is taken so that there is no modulo bias in the randomness returned
either by C<bytes> or its siblings, nor by C<string_from>. As a matter of
fact, this is exactly I<why> the C<string_from> method is preferable to
a home-grown solution. However, the algorithm to eliminate modulo bias can
impact the performance of the C<string_from> method. Any time the length of the
bag string is significantly less than the nearest greater or equal factor
of 2**32, performance will degrade. Unfortunately there is no known algorithm
that improves upon this situation. Fortunately, for sanely sized strings, it's
a minor issue. To put it in perspective, even in the case of passing a "bag"
string of length 2**31 (which is huge), the expected time to return random
bytes will only double.

=head1 INSTALLATION

This module should install without any fuss on modern versions of Perl. For
older Perl versions (particularly 5.6 and early 5.8.x's), it may be necessary
to update your CPAN installer to a more modern version before installing this
this module.

Test coverage for Bytes::Random::Secure is 100% (per Devel::Cover) on any
system that has L<Test::Warn> installed. But to keep the module light-weight,
Test::Warn is not dragged in by default at installation time.

=head1 AUTHOR

David Oswald C<< <davido [at] cpan (dot) org> >>

=head1 BUGS

Please report any bugs or feature requests to 
C<bug-bytes-random-secure at rt.cpan.org>, or through the web interface at 
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Bytes-Random-Secure>.  I will 
be notified, and then you'll automatically be notified of progress on your bug 
as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Bytes::Random::Secure


You can also look for information at:

=over 4

=item * Github Repo: L<https://github.com/daoswald/Bytes-Random-Secure>

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Bytes-Random-Secure>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Bytes-Random-Secure>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Bytes-Random-Secure>

=item * Search CPAN

L<http://search.cpan.org/dist/Bytes-Random-Secure/>

=back

=head1 ACKNOWLEDGEMENTS

Dana Jacobsen ( I<< <dana@acm.org> >> ) for his work that led to
L<Crypt::Random::Seed>, thereby significantly reducing the dependencies while
improving the portability and backward compatibility of this module.  Also for
providing a patch to this module that greatly improved the performance
of C<random_bytes>.

Dana Jacosen also provided extensive input, code reviews, and testing that 
helped to guide the direction this module has taken.  The code for the
FIPS-140-1 tests was taken directly from L<Crypt::Random::TESHA2>.  Thanks!

L<Bytes::Random> for implementing a nice, simple interface that this module
patterns itself after.

=head1 LICENSE AND COPYRIGHT

Copyright 2012 David Oswald.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

