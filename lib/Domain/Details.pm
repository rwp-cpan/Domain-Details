# PODNAME: Domain::Details
# ABSTRACT: Domain class with DNS/SSL/WHOIS fields

use v5.36;
use autouse 'Carp' => qw( carp croak );
use autouse 'Data::Printer' => qw( p );
use Object::Pad 0.78 ':experimental(init_expr)';

package Domain::Details;

# @formatter:off
class Domain::Details :strict( params ) :does(Domain::Details::SSL) {
# @formatter:on

  use experimental qw( try );
  use Syntax::Keyword::Match;
  use Net::Domain::ExpireDate; # Function: expire_date
  use Domain::PublicSuffix;    # Method: get_root_domain
  use POSIX;                   # Functions: setlocale, LC_ALL
  use Net::DNS;
  use Geo::IP;
  use Term::ANSIColor qw( colorstrip );
  use Clipboard; # Class method: copy_to_all_selections

  # @formatter:off

  field $domain :param :reader;

=method domain

Returns the current domain as created with the C<new> constructor

=cut

  field $description :param :accessor = undef;

=method description

Returns or sets an optional description (comment) on the domain object

=cut

  method whois_expiration ( $format //= '%B %d, %Y' ) {
    my $publicsuffix = Domain::PublicSuffix -> new;
    setlocale( LC_ALL , 'en_US.UTF-8' );
    return expire_date( $publicsuffix -> get_root_domain( $domain ) , $format ); # domain without the www. prefix
  }

=method whois_expiration

Returns domain's expiration date using the L<Net::ExpireDate> module's C<expire_date> function

Derives the root domain using L<Domain::PublicSuffix> class' C<get_root_domain> method

Accepts optional argument to specify the format the date is returned in

=cut

  method dns ( ) {
  # @formatter:on
    my $resolver = Net::DNS::Resolver -> new;
    my $geo = Geo::IP -> open( '/usr/share/GeoIP/GeoIP.dat' );
    # Set path explicitly because Perlbrew 5.36 on Debian fails to open for searching in /usr/local when Geo::IP is being installed with "cpan"
    # Installing the Debian package libgeo-ip-perl probably fixes that

    my ( $cname , $ptr );

    my $a = $resolver -> query( $domain , 'A' );
    my @a = $a -> answer if defined $a;

    my $mx = $resolver -> query( $domain , 'MX' );
    my @mx = $mx -> answer if defined $mx;

    my $ns = $resolver -> query( $domain , 'NS' );
    my @ns = $ns -> answer if defined $ns;

    my $txt = $resolver -> query( $domain , 'TXT' );
    my @txt = $txt -> answer if defined $txt;

    my $soa = $resolver -> query( $domain , 'SOA' );
    my @soa = $soa -> answer if defined $soa;

    my $answer;

    my %dns = (
      a     => [] ,
      cname => '' ,
      ptr   => [] ,
      mx    => [] ,
      ns    => [] ,
      txt   => [] ,
    ); # to push individual record values here

    for my $record ( @a , @mx , @ns , @txt , @soa ) {
      match( $record -> type : eq )
      {
        case( 'A' )
        {
          $answer .= sprintf( "A:\t%s (%s)\n" , $record -> address , $geo -> country_code_by_addr( $record -> address ));
          push( $dns{a} -> @* , $record -> address );
          $ptr = $resolver -> query( $record -> address , 'PTR' ); # Net::DNS::Packet
          if ( $ptr ) {
            my @ptr = $ptr -> answer; # [ Net::DNS:RR, ... ]
            $answer .= Term::ANSIColor::colored( [ 'bright_cyan' ] , sprintf( "P:\t%s (%s)\n" , $ptr[0] -> ptrdname , $geo -> country_code_by_name( $ptr[0] -> ptrdname )));
            # eq. rdatastr (undocumented)
            push( $dns{ptr} -> @* , $ptr[0] -> ptrdname );
          }
        }
        case( 'CNAME' )
        {
          # fetched by A, for instance
          $cname = Term::ANSIColor::colored( [ 'bright_magenta' ] , sprintf( "C:\t%s (%s)\n" , $record -> cname , $geo -> country_code_by_name( $record -> cname )));
          # 4 - 5 times (seemingly by A)
          $dns{cname} = $record -> cname;
        }
        case( 'MX' )
        {
          $answer .= Term::ANSIColor::colored( [ 'bright_yellow' ] , sprintf( "M:\t%s (%s)\n" , $record -> exchange , $geo -> country_code_by_name( $record -> exchange )));
          push( $dns{mx} -> @* , $record -> exchange );
        }
        case( 'NS' )
        {
          $answer .= Term::ANSIColor::colored( [ 'bright_green' ] , sprintf( "N:\t%s (%s)\n" , $record -> nsdname , $geo -> country_code_by_name( $record -> nsdname )));
          push $dns{ns} -> @* , $record -> nsdname;
        }
        case( 'TXT' )
        {
          $answer .= Term::ANSIColor::colored( [ 'bright_white' ] , sprintf( "T:\t%s\n" , $record -> txtdata ));
          push $dns{txt} -> @* , $record -> txtdata;
        }
        case( 'SOA' )
        { # fetched by A, for instance
          $answer .= Term::ANSIColor::colored(
            [ 'bright_red' ] ,
            sprintf( "S:\t%s %s\n" ,
              $record -> mname ,
              $record -> rname
            )
          );
        }
      }

    }

    $answer = $answer . $cname if defined $cname;
    return $answer;
  }

=method dns

L<Net::DNS> records (A, CNAME, MX, NS, TXT, and SOA) with with L<Geo::IP>

Uses L<Syntax::Keyword::Match> to topicalize C<< $record - >> type>

=cut

  # @formatter:off
  method summary () {
  # @formatter:on

    my $summary = <<~ "SUMMARY";
    SSL Expiration   : @{[$self -> ssl_expiration]} @{[$self -> ssl_expires_soon ? '(Expires Soon)' : '' ]}
    SSL Issue        : @{[$self -> ssl_issue]}
    WHOIS Expiration : @{[$self -> whois_expiration]}

    DNS              :

    @{[$self->dns]}
    SUMMARY
    say $summary;
    Clipboard -> copy_to_all_selections( colorstrip $summary );
  }

=method summary

Output summary, and copy it into the clipboard stripping colors with L<C<colorstrip>|Term::ANSIColor/colorstrip(STRING[, STRING ...])>

=cut

}
