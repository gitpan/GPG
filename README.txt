NAME
    GPG - a Perl2GnuPG interface

DESCRIPTION
    GPG.pm is a Perl5 interface for using GnuPG. GPG work with
    $scalar (string), as opposite to the existing Perl5 modules
    (GnuPG.pm and GnuPG::Interface)

SYNOPSIS
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

      my $keys = $gpg->list_keys();
      my $sigd = $gpg->list_sig();

INSTALLATION
     % chown root /usr/local/bin/gpg ; chmod 4755 /usr/local/bin/gpg
     % perl Makefile.PL
     % make
     % make test
     % make install

METHODS
    Look at the "test.pl" and "quick_test.pl" for examples and more
    explanation.

    You can change "VERBOSE" to "1" in "test.pl" and restart the
    test, too.

    *gen_key %params*
         Parameters are :
         - key_size (see gnupg doc)
         - real_name (usually first name and last name, cannot be empty)
         - email (email address, cannot be empty)
         - comment (can be empty)
         - passphrase (*SHOULD* be at least 16 chars long...)

        Please note the keys are not imported after creation, please
        read "test.pl" for an example, or read the "list_packets"
        method description.

    *list_packets $packet*
        Give a packet description for public and secret keys, run
        "test.pl" with "VERBOSE=1" for a better description.

    *import_keys $key*
        Import the key(s) in the current keyring.

    *clearsign $key_id, $passphrase, $text*
        Clearsign the current text.

    *verify $signed_text*
        Verify a signature.

    *encrypt $text, ($dest_1, ...)*
        Encrypt.

    *decrypt $passphrase, $text*
        Decrypt (yes, really)

    *sign_encrypt $key_id, $passphrase, $text, ($dest_1, ...)*
        Sign and Encrypt.

    *decrypt_verify $passphrase, $text*
        Decrypt and verify signature.

    *list_keys()*
        List all keys from your standard pubring

    *list_sig()*
        List all keys and signatures from your standard pubring

    *delete_secret_key $key_id*
        No yet implemented, gnupg don't accpt this in batch mode.

    *delete_key $key_id*
        No yet implemented, gnupg don't accept this in batch mode.

FAQ
     Q: How does it work ?
     A: it uses IPC::Open3 to connect the 'gpg' program. 
    IPC::Open3 make the fork and manage the filehandles for you.

      Q: How secure is GPG ?
      A: As secure as you want... Be carefull. First, GPG is no 
    more secure as 'gpg'. 
    Second, all passphrases are stored in non-secure memory, unless
    you "chown root" and "chmod 4755" your script first. Third, your
    script probably store passpharses somewhere on the disk, and 
    this is *not* secure.

      Q: Why using GPG, and not GnuPG or GnuPG::Interface ??
      A: For its input/output, GnuPG.pm work only with filename 
    (you must write your parameters values in a file and pass 
    the filename to gnupg, and the result will be write in 
    anoter given file)
    GnuPG::Interface works with fileshandles, but is heavy 
    to use - all filehandle management is let to the user. 
    GPG work only with $scalar for both input and output. 
    As I develop for a web interface, I don't want to write 
    a new file each time I need to communicate with gnupg.

KNOWN BUGS
    Bug come (by me) only from gnupg, and *not* from Perl :

     - methods "delete_key" and "delete_secret_key" doesn't work, 
       not because a bug, but because gnupg cannot do that in batch mode.

    I hope a later version of gnupg will correct this issue...

TODO
     import_keys : no test for multiples import (of both public/secret keys)
     sign-key / lsign-key / export_key
     fast-import / update-trustdb
     fingerprint

     delete-key / delete-secret-key (waiting - not possible for now, see BUG)

SUPPORT
    Feel free to send me your questions and comments.

    Feedback is ALWAYS welcome !

    Commercial support on demand, but for most problem read the
    "Support" section on http://www.gnupg.org.

DOWNLOAD
    https://sourceforge.net/project/filelist.php?group_id=8630

    developpers info at https://sourceforge.net/projects/gpg

    doc and home-page at http://gpg.sourceforge.net/

SEE ALSO
     GnuPG            - http://www.gnupg.org
     GnuPG.pm         - input/output only throw file_name
     GnuPG::Interface - input/output only throw file_handles
                        see http://GnuPG-Interface.sourceforge.net/ or CPAN
     IPC::Open3       - communication with 'gpg', see "perldoc perlipc"

AUTHOR
    miles@_REMOVE_THIS_users.sourceforge.net,
    pf@_REMOVE_THIS_spin.ch

