# PODNAME: Domain::Details::SSL
# ABSTRACT: Domain role for SSL

use v5.36;
use Object::Pad 0.78 ':experimental(init_expr)';

package Domain::Details::SSL;
# Without "package" PAUSE complains: no indexable package statements could be found in the distro

role Domain::Details::SSL {

  use experimental qw( try );
  use Net::SSL::ExpireDate;

  # @formatter:off
  method ssl_expiration ( $format //=  "%s %s, %s" ) {
    my $domain = $self -> domain;
    my $ssl = Net::SSL::ExpireDate -> new( https => $domain );
    try {
      return sprintf $format ,
        $ssl -> expire_date -> month_name ,
        $ssl -> expire_date -> day ,
        $ssl -> expire_date -> year;
    }
    catch( $message ) { undef }
  }
  # @formatter:on

=method ssl_expiration

Return the SSL expiration date using L<Net::SSL::ExpireDate> class' C<expire_date> constructor returning a L<DateTime> object

Accepts an argument to loosely set the date format as Year, Month, Day in C<sprintf> syntax

=cut

  # @formatter:off
  method ssl_issue ( $format //=  "%s %s, %s" ) {
    my $domain = $self -> domain;
    my $ssl = Net::SSL::ExpireDate -> new( https => $domain );
    try {
      return sprintf $format ,
        $ssl -> begin_date -> month_name ,
        $ssl -> begin_date -> day ,
        $ssl -> begin_date -> year;
    }
    catch( $message ) { undef }
  }
  # @formatter:on

=method ssl_issue

Return the SSL issue date using L<Net::SSL::ExpireDate> class' C<begin_date> constructor returning a L<DateTime> object

Accepts an argument to loosely set the date format as Year, Month, Day in C<sprintf> syntax

=cut

  # @formatter:off
  method ssl_expires_soon ($format //= '14 days' ) {
    my $domain = $self -> domain;
    my $ssl = Net::SSL::ExpireDate -> new( https => $domain );
    try {
      $ssl -> is_expired( $format );
    }
    catch ( $message ) { undef }

  }
  # @formatter:on

=method ssl_expires_soon

Return a boolean indicating if the SSL expires within the time specified

Defaults to 14 days, ie. 2 weeks which is a normal renewal date

=cut

}