package GPG;
use strict;

  use vars qw/$VERSION/;
  $VERSION = "0.01";

  use IO::Handle;
  use IPC::Open3;

  sub new ($%) { my ($this,%params) = @_;
    my $class = ref($this) || $this;
    my $self  = {};
       $self->{'gnupg_path'}  = $params{'gnupg_path'}  || '/usr/local/bin';
       $self->{'homedir'}     = $params{'homedir'}     || '';
       $self->{'config'}      = $params{'config'}      || '';
       $self->{'armor'}       = $params{'armor'}       || '';
       $self->{'debug'}       = $params{'debug'}       || '';

       $self->{'COMMAND'}  = '';
       $self->{'COMMAND'} .= "$self->{'gnupg_path'}/gpg";
       $self->{'COMMAND'} .= " -a"                           if $self->{'armor'};
       $self->{'COMMAND'} .= " --config  $self->{'config'}"  if $self->{'config'};
       $self->{'COMMAND'} .= " --homedir $self->{'homedir'}" if $self->{'homedir'};
       $self->{'COMMAND'} .= " --batch";
       $self->{'COMMAND'} .= " --no-comment";
       $self->{'COMMAND'} .= " --no-version";
       $self->{'COMMAND'} .= ' '; # so i dont forget the spaces later :-)

      if ($self->{'debug'}) {
        print "\n********************************************************************\n";
        print "COMMAND : $self->{'gnupg_path'}/$self->{'COMMAND'}\n";
        print "\$self->{'homedir'} : $self->{'homedir'}\n";
        print "\$self->{'config'} : $self->{'config'}\n";
        print "\$self->{'armor'} : $self->{'armor'}\n";
        print "\$self->{'debug'} : $self->{'debug'}\n";
        print "********************************************************************\n";
      }

    bless $self, $class;
    return $self;
  }

    sub error { my ($this,$string) = @_;
      $this->{'err'} = $string;
      wait();
    }

    sub err { my ($this) = @_;
      my $stderr_msg = $this->{'err'};
      $this->{'err'} = '';
      return $stderr_msg;
    }

    sub start_gpg { my ($this,$command,$input) = @_;
      my ($stdin,$stdout,$stderr) = (IO::Handle->new(),IO::Handle->new(),IO::Handle->new());
      my $pid = open3($stdin,$stdout,$stderr, $command);
      $this->error("Cannot fork [COMMAND: '$command'].") and return (0) if !$pid;

      print $stdin $input;
      close $stdin;

      my $output = join('',<$stdout>);
      close $stdout;

      my $error = join('',<$stderr>);
      close $stderr;

      wait();

      if ($this->{'debug'}) {
        print "\n********************************************************************\n";
        print "COMMAND : \n$command [PID $pid]\n";
        print "STDIN  :  \n$input\n";
        print "STDOUT :  \n$output\n";
        print "STDERR :  \n$error\n";
        print "\n********************************************************************\n";
      }

      return($pid,$output,$error);
    }


### gen_key #####################################################

  sub gen_key($%) { my ($this,%params) = @_;
    my $key_size   = $params{'key_size'};
    $this->error("no key_size defined !")   and return if !$key_size;
    my $real_name  = $params{'real_name'};
    $this->error("no real_name defined !")  and return if !$real_name;
    my $email      = $params{'email'};
    $this->error("no email defined !")      and return if !$email;
    my $comment    = $params{'comment'} || '';
    my $passphrase = $params{'passphrase'};
    $this->error("no passphrase defined !") and return if !$passphrase;

    srand();
    my $tmp_filename = $this->{homedir}."/tmp_".sprintf("%08d",int(rand()*100000000));

    my $pubring    = "$tmp_filename.pub";
    my $secring    = "$tmp_filename.sec";

    my $script = '';
       $script .= "Key-Type: 20\n";
       $script .= "Key-Length: $key_size\n";
       $script .= "Name-Real: $real_name\n";
       $script .= "Name-Comment: $comment\n" if $comment;
       $script .= "Name-Email: $email\n";
       $script .= "Expire-Date: 0\n";
       $script .= "Passphrase: $passphrase\n";
       $script .= "\%pubring $pubring\n";
       $script .= "\%secring $secring\n";
       $script .= "\%commit\n";

    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.' --gen-key', $script);
    return if !$pid;

    # output of "gen_key" comes on stderr, we cannot stop here...
    #$this->error($error) and return if $error;

    open(*PUBRING,"$pubring");
    my @pubring = <PUBRING>;
    close PUBRING;
    unlink "$pubring" || die "cannot unlink '$pubring'";
    open(*SECRING,"$secring");
    my @secring= <SECRING>;
    close SECRING;
    unlink "$secring" || die "cannot unlink '$secring'";;

    return(join('',@pubring),join('',@secring));
  }


### list_packets ################################################

  sub list_packets {  my ($this,$string) = @_;
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.' --list-packets', $string);
    return if !$pid;

    return [] if $output !~ /^\s*\:\S+ key packet\:/; # no key found.

    $output =~ s/^\s*\:\S+ key packet\:\s*//;
    my @pubkeys = split(/\s*\n\:\S+ key packet\:\s*/,$output);
    my $res = [];
    for my $i (@pubkeys) { # for each keys found...
      my $hash = {};
      my @part = split(/\s*\n\:signature packet\:\s*/,$i);
      my $key  = shift @part;
      $key               =~ / created (\d+)/;
      $hash->{created}   =  $1 if $1;
      $key               =~ /\:user ID packet\: \"(.*)\"/;
      $hash->{user_id}   =  $1 if $1;
      $hash->{user_name} =  $hash->{user_id};
      $hash->{user_name} =~ s/\s[\(\<].*$//;
      $hash->{user_id}   =~ /\s\<(.*)\>$/;
      $hash->{user_mail} =  $1 if $1;
      $hash->{sig}       =  [];
      $key               =~ /\s(\w)key\[0\]\: \[(\d+) bits\]\s+/;
      $hash->{key_type}  =  'public' if $1 and $1 eq 'p';
      $hash->{key_type}  =  'secret' if $1 and $1 eq 's';
      $hash->{key_size}  =  $2 if $2;
      for my $j (@part) { # for all key_sig...
        my $sub_hash = {};
        $j                   =~ / keyid (\S*)\s/;
        $sub_hash->{key_id}  =  $1 if $1;
        $j                   =~ / created (\d*)\s/;
        $sub_hash->{created} =  $1 if $1;
        push @{$hash->{sig}},$sub_hash;
      }
      $hash->{key_id} = $hash->{sig}[0]{key_id};
      push @$res, $hash;
    }
    return $res;
  }


### import #################################################

  sub import_keys { my ($this,$import) = @_;
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.' --import', $import);
    return if !$pid;

    my $ok = '';
    if ($error =~ /\spublic key imported\s/m) {
      $error =~ /\sTotal number processed\: (\d+)\s/m;
      my $processed = $1 || '';
      $error =~ /\simported\: (\d+)\s/m;
      my $imported = $1 || '';
      $ok = "$processed public key imported" if $processed && $processed eq $imported;
    }
    elsif ($error =~ /\ssecret key imported\s/m) {
      $error =~ /\sTotal number processed\: (\d+)\s/m;
      my $processed = $1 || '';
      $error =~ /\ssecret keys imported\: (\d+)\s/m;
      my $imported = $1 || '';
      $ok = "$1 secret key imported" if $processed && $processed eq $imported;
    }
    $this->error($error) and return if !$ok;

    return $ok;
  }


### sign ###################################################

  sub clearsign { my ($this,$key_id,$passphrase,$text) = @_;
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--passphrase-fd 0 --default-key $key_id --clearsign", "$passphrase\n$text");
    return if !$pid;

    $this->error($error) and return if $error;
    return $output;
  }


### verify #################################################

  sub verify { my ($this,$string) = @_;
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--verify", "$string");
    return if !$pid;

    my $verify = {};
    $verify->{'ok'}       =  $error =~ /\sGood signature from \"/m ? 1 : 0;
    $error                =~ / signature from \"(.*)\"\s/m;
    $verify->{'key_user'} =  $1 if $1;
    $error                =~ /\susing \w+ key ID (\w+)\s/m;
    $verify->{'key_id'}   =  $1 if $1;
    $error                =~ /\sSignature made (.*) using\s/m;
    $verify->{'sig_date'} =  $1 if $1;

    return $verify;
  }


### encrypt ################################################

  sub encrypt { my ($this,$text,@dest) = @_;
    my $dest = '-r '.join(' -r ',@dest);
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "$dest --encrypt", "$text");
    return if !$pid;

    $this->error($error) and return if $error;
    return $output;
  }


### decrypt ################################################

  sub decrypt { my ($this,$passphrase,$text) = @_;
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--passphrase-fd 0 --decrypt", "$passphrase\n$text");
    return if !$pid;

    $this->error($error) and return if $error;
    return $output;
  }


### sign_encrypt ###########################################

  sub sign_encrypt { my ($this,$key_id,$passphrase,$text,@dest) = @_;
    my $dest = '-r '.join(' -r ',@dest);
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--passphrase-fd 0 $dest --default-key $key_id -se", "$passphrase\n$text");
    return if !$pid;

    $this->error($error) and return if $error;
    return $output;
  }


### decrypt_verify #########################################

  sub decrypt_verify { my ($this,$passphrase,$text) = @_;
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--passphrase-fd 0", "$passphrase\n$text");
    return if !$pid;

    my $verify = {};
    $verify->{'ok'}       =  $error =~ /\sGood signature from \"/m ? 1 : 0;
    $error                =~ / signature from \"(.*)\"\s/m;
    $verify->{'key_user'} =  $1 if $1;
    $error                =~ /\susing \w+ key ID (\w+)\s/m;
    $verify->{'key_id'}   =  $1 if $1;
    $error                =~ /\sSignature made (.*) using\s/m;
    $verify->{'sig_date'} =  $1 if $1;

    $verify->{'text'}     = $output;

    return $verify;
  }

### list_keys ##############################################

    sub build_list_keys { my ($text) = @_;
      my $list = [];
      my $last_key_sig = [];
      for my $i (split(/\n/,$text)) {
        my @line = split(/\:/,$i);
        next if @line < 3; # not a descriptor line...

        my $hash = {};
        $hash->{'type'}       = $line[0];
        $hash->{'trust'}      = $line[1];
        $hash->{'key_size'}   = $line[2];
        $hash->{'algo'}       = $line[3];
        $hash->{'key_id'}     = $line[4];
        $hash->{'created'}    = $line[5];
        $hash->{'expiration'} = $line[6];
        $hash->{'local_id'}   = $line[7];
        $hash->{'ownertrust'} = $line[8];
        $hash->{'user_id'}    = $line[9];

        $hash->{'trust'} = 0 if !$line[1] || ($line[1] ne 'm' && $line[1] ne 'f' && $line[1] ne 'u'); # no trust
        $hash->{'sig'}   = []  and $last_key_sig = $hash->{'sig'} if $hash->{'type'} ne 'sig';
        push @$last_key_sig,$hash and next if $hash->{'type'} eq 'sig';
        
        push @$list,$hash;
      }
      return $list;
    }

  sub list_keys { my ($this) = @_;
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--with-colons --list-keys", "");
    return if !$pid;
    $this->error($error) and return if $error;

    return build_list_keys($output);
  }


### list_sig ##############################################

  sub list_sig { my ($this) = @_;
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--with-colons --list-sig", "");
    return if !$pid;
    $this->error($error) and return if $error;
    return build_list_keys($output);
  }


### PROTOTYPE ##############################################

  sub prototype { my ($this) = @_;
    return; # XXX 'prototype' : only as example if you would add new function
    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--passphrase-fd 0", "");
    return if !$pid;
    $this->error($error) and return if $error;

    return $output;
  }


### delete_key #############################################

  sub delete_key { my ($this,$key_id) = @_;
    warn "Not yet implemented - read the doc please." and return;

    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--delete-key $key_id", "y\n");
    return if !$pid;

    $this->error($error) and return if $error;
  }


### delete_secret_key ######################################

  sub delete_secret_key { my ($this,$key_id) = @_;
    warn "Not yet implemented - read the doc please." and return;

    my ($pid,$output,$error) = start_gpg($this,$this->{'COMMAND'}.
         "--delete-secret-key $key_id", "y\n");
    return if !$pid;

    $this->error($error) and return if $error;
  }


=head1 NAME

GPG - a Perl2GnuPG interface

=head1 DESCRIPTION

GPG.pm is a Perl5 interface for using GnuPG. GPG work with $scalar (string), 
as opposite to the existing Perl5 modules GnuPG.pm (which work only 
with filename...) and GnuPG::Interface (which work with fileshandles, 
but is heavy to use - all filehandle management is let to the user)

=head1 SYNOPSIS

  use GPG;

    my ($passphrase,$key_id) = ("1234567890123456",'');

  my $gpg = new GPG(homedir  => './test'); # Creation

  die $gpg->err() if $gpg->err(); # Error handling

  my ($pubring,$secring) = $gpg->gen_key(key_size => "512",
                                        real_name  => "Joe Test",
                                        email      => 'nobody@yahoo.com',
                                        comment    => "",
                                        passphrase => $passphrase);

  my $pubkey = $gpg->list_packets($pubring);
  my $seckey = $gpg->list_packets($secring);
  $key_id = $pubkey->[0]{'key_id'};


  $gpg->import_keys($secring);
  $gpg->import_keys($pubring);

  my $signed = $gpg->clearsign($key_id,$passphrase,"TEST_TEXT");
  my $verify = $gpg->verify($signed);

  my $TEST_TEXT = $gpg->encrypt("TEST_TEXT",$key_id);
     $TEST_TEXT = $gpg->decrypt($passphrase,$TEST_TEXT);

     $TEST_TEXT = $gpg->sign_encrypt($key_id,$passphrase,$TEST_TEXT,$key_id);
  my $decrypt_verify = $gpg->decrypt_verify($passphrase,$TEST_TEXT);


=head1 INSTALLATION

 % chown root /usr/local/bin/gpg ; chmod 4755 /usr/local/bin/gpg
 % perl Makefile.PL
 % make
 % make test
 % make install

=head1 METHODS

Look at the "test.pl" and "quick_test.pl" for examples and more explanation.

You can change "VERBOSE" to "1" in "test.pl" and restart the test, too.

=over 4

=item I<gen_key %params>

 Parameters are :
 - key_size (see gnupg doc)
 - real_name (usually first name and last name, cannot be empty)
 - email (email address, cannot be empty)
 - comment (can be empty)
 - passphrase (*SHOULD* be at least 16 chars long...)

Please note the keys are not imported after creation, please read "test.pl" for an example,
or read the "list_packets" method description.

=item I<list_packets $packet>

Give a packet description for public and secret keys, run "test.pl"
with "VERBOSE=1" for a better description.

=item I<import_keys $key>

Import the key(s) in the current keyring.

=item I<clearsign $key_id, $passphrase, $text>

Clearsign the current text.

=item I<verify $signed_text>

Verify a signature.

=item I<encrypt $text, ($dest_1, ...)>

Encrypt.

=item I<decrypt $passphrase, $text>

Decrypt (yes, really)

=item I<sign_encrypt $key_id, $passphrase, $text, ($dest_1, ...)>

Sign and Encrypt.

=item I<decrypt_verify $passphrase, $text>

Decrypt and verify signature.

=item I<delete_secret_key $key_id>

No yet implemented, gnupg don't accpt this in batch mode.

=item I<delete_key $key_id>

No yet implemented, gnupg don't accept this in batch mode.

=back

=head1 FAQ

 Q: How does it work ?
 A: it uses IPC::Open3 to connect the 'gpg' program. 
IPC::Open3 make the fork and manage the filehandles for you.

  Q: How secure is GPG ?
  A: Not very secure. First, GPG is no more secure as 'gpg'. 
Second, all passphrases are stored in non-secure memory, unless
you "chown root" and "chmod 4755" your script first. Third, your
script probably store passpharses somewhere on the disk, and 
this is *not* secure.

  Q: Why using GPG, and not GnuPG or GnuPG::Interface ??
  A: For its input/output, GnuPG.pm work only with filename. 
GnuPG::Interface works with fileshandles, but is heavy to use - all filehandle management 
is let to the user. GPG work only with $scalar for both input and output. As I develop for a
web interface, I don't want to write a new file each time I need to communicate with gnupg.

=head1 KNOWN BUGS

Bug come (by me) only from gnupg, and *not* from Perl :

 - methods "delete_key" and "delete_secret_key" doesn't work, 
   not because a bug, but because gnupg cannot do iti in batch mode.

I hope a later version of gnupg will correct this issue...

=head1 TODO

 import_keys : no test for multiples import (of both public/secret keys)
 sign-key / lsign-key / export_key
 fast-import / update-trustdb
 fingerprint
 list-keys /list-sign

 delete-key / delete-secret-key (waiting - not possible for now, see BUG)

=head1 SUPPORT

Feel free to send me your questions and comments.

Commercial support on demand, but for most problem read the "Support" section
on http://www.gnupg.org.

=head1 DOWNLOAD

https://sourceforge.net/project/filelist.php?group_id=8630

developpers info at https://sourceforge.net/projects/gpg

doc and home-page at http://gpg.sourceforge.net/

=head1 SEE ALSO

 GnuPG            - http://www.gnupg.org
 GnuPG.pm         - input/output only throw file_name
 GnuPG::Interface - input/output only throw file_handles
                    see http://GnuPG-Interface.sourceforge.net/ or CPAN
 IPC::Open3       - communication with 'gpg', see "perldoc perlipc"

=head1 AUTHOR

miles@_REMOVE_THIS_users.sourceforge.net, pf@_REMOVE_THIS_spin.ch

=cut
1; # End.
