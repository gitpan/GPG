#!/usr/bin/perl -w
use strict;
use Data::Dumper;

  use GPG;

  my $VERBOSE = 0;
  my $DEBUG   = 0;

  my @test = qw/ new gen_key list_packets import_keys 
                 clearsign verify
                 encrypt decrypt
                 sign_encrypt decrypt_verify 
                 list_keys list_sig /;
               #  delete_secret_key delete_key /; not yet implemented - read the doc please

  my $gpg;
  my ($pubring,$secring,$signed) = ('','');
  my $passphrase = '1234567890123456';
  my $key_id     = '';
  my $TEST_TEXT  = "this is a text to encrypt/decrypt/sign/etc.\nand a second line...";

  test();

######################################################

  sub debug { my ($msg) = @_;
    print "\n\n$msg\n------------------------------------------\n" if $VERBOSE;
  }

  sub test {
    my $count = -1;
    local $| = 1;
    for my $i (@test) {
      no strict 'refs';
      $count++;
      print "test ",sprintf("%2d",$count)," $i",substr("....................",0,(20-length($i)));
      eval { &$i };
      if($@) { 
        chomp($@);
        print " NOT ok -- $@\n";
      }
      else {
        print " ok.\n";
      }
    }
  }

  sub new {
    $gpg = new GPG(homedir => './test',
                   armor   => '1',
                   debug   => $DEBUG);
    die $gpg->err() if $gpg->err();
    debug("New GPG object successfully created");
  }

  sub gen_key {
    ($pubring,$secring) = $gpg->gen_key(key_size   => "512",
                                        real_name  => "Joe Test",
                                        email      => 'nobody@yahoo.com',
                                        comment    => "",
                                        passphrase => $passphrase);
    die $gpg->err() if $gpg->err();
    debug("----> pubring:\n$pubring\n----> secring:\n$secring");
  }

  sub list_packets {
    my $pubkey = $gpg->list_packets($pubring);
    my $seckey = $gpg->list_packets($secring);
    
    die $gpg->err() if $gpg->err();
    $key_id = $seckey->[0]{'key_id'};
    if ($VERBOSE) {
      my $dump = Data::Dumper->new([$pubkey,$seckey]);
      debug($dump->Dump.$dump->Dump);
    }
  }

  sub import_keys {
    my $import_pub = $gpg->import_keys($pubring);
    die $gpg->err() if $gpg->err();
    my $import_sec = $gpg->import_keys($secring);
    die $gpg->err() if $gpg->err();
    debug("Ok: $import_pub and $import_sec successfully.");
  }

  sub clearsign { 
    $signed = $gpg->clearsign($key_id,$passphrase,$TEST_TEXT);
    debug("signed text :\n$signed");
  }

  sub verify {
    my $verify = $gpg->verify($signed);
    if ($VERBOSE) {
      my $dump = Data::Dumper->new([$verify]);
      debug($dump->Dump);
    }
  }

  sub encrypt {
    $TEST_TEXT = $gpg->encrypt($TEST_TEXT,$key_id);
    debug("encrypted text :\n$TEST_TEXT");
  }

  sub decrypt {
    $TEST_TEXT = $gpg->decrypt($passphrase,$TEST_TEXT);
    debug("decrypted text :\n$TEST_TEXT");
  }

  sub sign_encrypt {
    $TEST_TEXT = $gpg->sign_encrypt($key_id,$passphrase,$TEST_TEXT,$key_id);
    debug("signed and encrypted text :\n$TEST_TEXT");
  }

  sub decrypt_verify {
    my $decrypt_verify = $gpg->decrypt_verify($passphrase,$TEST_TEXT);
    if ($VERBOSE) {
      my $dump = Data::Dumper->new([$decrypt_verify]);
      debug($dump->Dump);
    }
  }

  sub list_keys {
    my $list_keys = $gpg->list_keys();
    if ($VERBOSE) {
      my $dump = Data::Dumper->new([$list_keys]);
      debug($dump->Dump);
    }
  }

  sub list_sig {
    my $list_sig = $gpg->list_sig();
    if ($VERBOSE) {
      my $dump = Data::Dumper->new([$list_sig]);
      debug($dump->Dump);
    }
  }

  sub delete_secret_key {
    $gpg->delete_secret_key($key_id);
    debug("secret key removed from key_ring");
  }

  sub delete_key {
    $gpg->delete_key($key_id);
    debug("public key removed from key_ring");
  }


# End of 'test.pl'.
