=head1 Bytes-Random-Secure-Tiny
The minimal stuff needed from Bytes::Random::Secure, with no dependencies.

=head1 Description

The CPAN Module L<Bytes::Random::Secure> produces high quality randomness using the ISAAC algorithm, seeded using
entropy sources on a wide variety of operating systems.  It has quite a few options for configurability.  And
provides both a functions and an object interface.  But it has several dependencies, and its configurability,
flexible and useful, may be more complexity than most use-cases require.

Bytes::Random::Secure::Tiny's goal is to have no dependencies outside of the Perl core, and for the most part,
a simple interface that presents a minimal amount of configuration.  We essentially asked ourselves, what
are the essentials, and how can we achieve them in the most light-weight way?  This module is the answer
we came up with.
