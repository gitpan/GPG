#!/usr/bin/perl -w
use strict;

  use GPG;

    my ($passphrase,$key_id) = ("1234567890123456",'');

  my $gpg = new GPG(homedir  => './test'); # Creation

  die $gpg->err() if $gpg->err(); # Success ?

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


# End.
