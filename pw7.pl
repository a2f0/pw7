#!/usr/bin/env perl -w
#http://www.perlmonks.org/?node_id=522597

use warnings;
use strict;
use Crypt::OpenPGP;
use Expect;
use File::Path 'rmtree';
use Getopt::Std;
use IO::Prompt;
use IO::Stty;
use Sys::Hostname; #to get the hostname
use Term::ReadLine; #used for the menuing system
use Term::ReadKey;

#This untaints the environment path
$ENV{'PATH'} = '/bin:/usr/bin';

package pw7;

my $version = "0.1b";

my @ISA = qw(Exporter);
my @EXPORT = qw(signalHandler);
my %commandLineOptions;
Getopt::Std::getopts('hvdt', \%commandLineOptions);

$SIG{'QUIT'} = \&signalHandler; 
$SIG{'TERM'} = \&signalHandler;
$SIG{'KILL'} = \&signalHandler;
$SIG{'INT'} = \&signalHandler;

my $env;
$env->{'commandlineoptions'} = \%commandLineOptions;
$env->{'loginName'} = getlogin();

$env = pw7::init($env); 
$env = pw7::logMeIn($env);
$env = pw7::main($env);

sub main {
    my $environment = $_[0] or die "Print menu called without environment.\n";  
    pw7::printDebug($environment, "Main called.\n");
    my $term = Term::ReadLine->new('Password');
    my $prompt = $environment->{'prompt'};
    while ( defined ($_ = $term->readline($environment->{'prompt'}))) 
    { 
            ($_ eq '?' || $_ eq 'help') && do { 
                    pw7::printRegularMenu($environment);
                    next; 
            }; 
            (/^init/) && do {
            $environment = pw7::initUser($environment); 
            if ($environment->{'errorLevel'} eq '0') { 
                print "Environment initialized successfully.\n";                
            } else {
                print "Environment initialize failed: " . $environment->{'errorString'} . "\n"; 
                delete $environment->{'errorString'};
                $environment->{'errorLevel'}=0;
            }
            next;   
        };
        (/^login/) && do {
                    pw7::logMeIn($environment, "Password: ");
                    next;
            };
            (/^get/) && do {
            my @arg = split(/\s+/, $_);
            $environment->{'itemName'} = $arg[1];
            $environment->{'fromLoginIndicator'} = '0';
            $environment->{'itemPath'} = $environment->{'itemsPath'};   
            pw7::getItem($environment);
            delete $environment->{'itemPath'};
            next;
        };
        (/^full/) && do {
            my @arg = split(/\s+/, $_);
            $environment->{'itemName'} = $arg[1];
            $environment->{'fromLoginIndicator'} = '0';
            $environment->{'itemPath'} = $environment->{'itemsPath'};   
            $environment->{'getFull'} = '1';
            pw7::getItem($environment);
            delete $environment->{'itemPath'};
            next;
        };
        (/^create/) && do {
            $environment = pw7::checkLocked($environment); 
            
            if ($environment->{'isLocked'}) {
                print "User " . $environment->{'lockedBy'} . " has the application locked with PID " . $environment->{'lockPID'} . ".\n";    
                next;
            } else {
                $environment = pw7::lockApplication($environment);
                my @arg = split(/\s+/, $_);
                $environment->{'itemName'} = $arg[1];
                $environment = pw7::newItem($environment);
                $environment = pw7::unlockApplication($environment);
                next;
            }
        };
            (/^passwd/) && do {
            $environment = pw7::changePassword($environment);           
            next;   
        };
        (/^auth/) && do {
            $environment = pw7::checkLocked($environment); 
            if ($environment->{'isLocked'}) {
                print "User " . $environment->{'lockedBy'} . " has the application locked with PID " . $environment->{'lockPID'} . ".\n";    
            } else {
                $environment = pw7::lockApplication($environment);
                my @arg = split(/\s+/, $_);
                $environment->{'itemName'} = $arg[1];
                pw7::authItem($environment);
                $environment = pw7::unlockApplication($environment);
            }
            next;
        };
        (/^set/) && do {    
            $environment = pw7::checkLocked($environment);  
            if ($environment->{'isLocked'}) {
                print "User " . $environment->{'lockedBy'} . " has the application locked with PID " . $environment->{'lockPID'} . ".\n";
            } else {
                $environment = pw7::lockApplication($environment);
                my @arg = split(/\s+/, $_);
                $environment->{'itemName'} = $arg[1];
                $environment = pw7::setItem($environment);  
                $environment = pw7::unlockApplication($environment);
            }       
            next;
        };
        (/^delete/) && do {
            $environment = pw7::checkLocked($environment);
            if ($environment->{'isLocked'}) {
                print "User " . $environment->{'lockedBy'} . " has the application locked with PID " . $environment->{'lockPID'} . ".\n";
            } else {
                $environment = pw7::lockApplication($environment);          
                my @arg = split(/\s+/, $_);
                if ( defined $arg[1]) {
                    pw7::printDebug($environment, "deleting Item: " . $arg[1] . "\n");  
                    $environment->{'itemName'} = $arg[1];
                    $environment = pw7::deleteItem($environment);   
                    $environment = pw7::unlockApplication($environment);
                } else {
                    print "Pass an item name as a parameter.\n";
                }
            }
            next;
        };
        (/^quit/ || /^exit/) && do { 
                $environment = pw7::logMeOut($environment);
            last; 
        }; 
            ($_ eq 'logout') && do {
                    $environment = pw7::logMeOut($environment);
            next;
            };
            ($_ eq 'p') && do {
                    $environment = pw7::printHashReference($environment);
                    next;
            };
            ($_ eq 'a' || $_ eq 'ahelp') && do {
            pw7::printAdvancedMenu($environment);   
            next;
        };
            ($_ eq 'lm') && do { 
                pw7::listMasterPublicKeys($environment);
                    next;
            };
            ($_ eq 'lh') && do {
                    pw7::listHomePrivateKeys($environment);
                    next;
            };
        ($_ eq 'g') && do {
            $environment = pw7::checkLocked($environment); 
            if ($environment->{'isLocked'}) {
                print "User " . $environment->{'lockedBy'} . " has the application locked with PID " . $environment->{'lockPID'} . ".\n";    
                next;
            } else {
                $environment = pw7::lockApplication($environment);
                pw7::generateKeys($environment, $environment->{'loginName'} . "-Pw7");
                $environment = pw7::unlockApplication($environment);
                next;
            }
            };
        ($_ eq 's') && do {
            $environment = pw7::checkLocked($environment); 
            pw7::printDebug($environment, "Submit personal called.\n");
            if ($environment->{'isLocked'}) {
                print "User " . $environment->{'lockedBy'} . " has the application locked with PID " . $environment->{'lockPID'} . ".\n"; 
                next;
            } else {
                $environment = pw7::lockApplication($environment);
                        &addPersonalPublicToMaster($environment);
                        $environment = pw7::unlockApplication($environment);
                next;
            }
        };
        ($_ eq 'e') && do {
                    if ($environment->{'userFullyAuthenticated'} eq '0') {
                print "Login first (login).";       
            } elsif ($environment->{'userFullyAuthenticated'} eq '1')  {
                        $environment = pw7::readAuthFileFromDisk($environment);
            } 
                    next;
            };
        ($_ eq 't') && do {
                    pw7::toggleVerbose($environment);
                    next;
            };
            ($_ eq 'hm') && do {
                    pw7::printUserNametoHexKeyMappings($environment, "master");
                    next;
            };
            ($_ eq 'hp') && do {
                    pw7::printUserNametoHexKeyMappings($environment, "private");
                    next;
        }; 
        ($_ eq 'list') && do {
                    pw7::listItems($environment);
                    next;
            };
        ($_ eq 'r') && do {


            pw7::printAuthorizationsDataStructure($environment);
                    next;
            };
        ($_ eq 'c') && do {
                    pw7::createDummyEncryptedFile($environment);
                    next;
        };
        ($_ eq 'l') && do {
                    $environment = pw7::lockApplication($environment);
                    next;
            };
        ($_ eq 'u') && do {
                    $environment = pw7::unlockApplication($environment);
                    next;
            };
        ($_ eq 'd') && do {
                    $environment = pw7::deleteEverythingAndStartOver($environment);
            next;
            };
        ($_ eq 'fc') && do {
            $environment = pw7::doFileAndPermissionChecks($environment);
            next;
            };
        #write the authorization table to disk
        ($_ eq 'w') && do {
            $environment = pw7::checkLocked($environment); 
            if ($environment->{'isLocked'}) {
                print "User " . $environment->{'lockedBy'} . " has the application locked with PID " . $environment->{'lockPID'} . ".\n";    
                next;
            } else {
                $environment = pw7::lockApplication($environment);
                &writeAuthorizationsTableToDisk($environment);
                $environment = pw7::unlockApplication($environment);
                next;
            }
        };
        ($_ eq 'wh') && do {
            $environment = pw7::checkLocked($environment);
            if ($environment->{'isLocked'}) {
                print "User " . $environment->{'lockedBy'} . " has the application locked with PID " . $environment->{'lockPID'} . ".\n";    
                next;   
            } else {
                print "The application isn't locked.\n";
                next;
            }
        };
            ($_ eq 'f') && do {
            $environment = pw7::checkLocked($environment); 
            if ($environment->{'isLocked'}) {
                $environment = pw7::forceUnlock($environment);
                next;
            } else {
                print "The application is not locked.\n";
                next;
            }
        };
            ($_ eq 'cl') && do {
            $environment = pw7::checkLocked($environment); 
            print "Locked status: " . scalar($environment->{'isLocked'}) . "\n";
            next;
        };
        ($_ eq 'ch') && do { 
                $environment = pw7::changeLoginName($environment);
            next; 
            }; 
        do {
                    print "Invalid menu command (try ? for help).\n"; 
        } 
    } 
    return $environment;
}

sub init {
    my $environment = $_[0] or die "Init called without environment\n";
    #print these should probably be tuned
    $environment->{'gpgPath'} = '/usr/local/bin/gpg';
    #this should print out the PID of every process on the system
    $environment->{'pscmd'} = '/bin/ps -ef | awk \'{print $2}\'';
    $environment->{'applicationData'} = '/var/tmp/pw7/'; 
    #took a slash out on the line below
    $environment->{'applicationRootData'} = '/var/tmp/pw7'; 

    #these generally don't need to be tuned
    $environment->{'homepath'} = $ENV{HOME};
    $environment->{'authFile'} = $environment->{'applicationData'} . 'pw7.auth';
    $environment->{'encryptedauthFile'} = $environment->{'applicationData'} . 'pw7.encryptedauth';
    $environment->{'itemsPath'} = $environment->{'applicationRootData'} . 'items/';
    $environment->{'homeKeyPath'} = $environment->{'homepath'} . '/.pw7/' . $environment->{'loginName'}; 
    $environment->{'homeKeyRoot'} = $environment->{'homeKeyPath'} . '/personalkeyring';
    $environment->{'masterPublicKeyringPath'} = $environment->{'applicationRootData'}; 
    $environment->{'lockFilePath'} = $environment->{'applicationData'}; 
    $environment->{'masterPublicKeyring'} = $environment->{'masterPublicKeyringPath'} . '/pubring.gpg';
    $environment->{'homePublicKeyring'} = $environment->{'homeKeyPath'} . "/pubring.gpg";  
    $environment->{'homePrivateKeyring'} = $environment->{'homeKeyPath'} . "/secring.gpg";
    $environment->{'keySize'} = '1024';
    $environment->{'term'} = Term::ReadLine->new('Password');
    $environment->{'prompt'} = $environment->{'loginName'} . '@pw7> ';
    $environment->{'passphrase'} = '';
    $environment->{'keyValidityTimeInDays'} = '0'; #maybe implement expiring keys, key rotation later
    $environment->{'hostname'} = Sys::Hostname::hostname();
    $environment->{'termreadlineconf'} = $environment->{'term'}->Attribs();
    $environment->{'passphraseValidated'} = '0';
    $environment->{'verbose'} = 'false';    
    $environment->{'rootKeyName'} = 'pw7-rootcert';
    $environment->{'maxItemNameLength'} = '33';
    $environment->{'errorLevel'} = '0';
    $environment->{'requiresignedauth'} = '0';
    $environment->{'errorLevel'} = '0';         
    $environment->{'currentPID'} = "$$";
    $environment->{'isPasswordRotating'} = '0';
    $environment->{'developerMode'} = '0';
    $environment->{'timestamp'} = localtime(time);
    $environment->{'userFullyAuthenticated'} = '0';
    $environment->{'getFull'} = '0';
    if ($environment->{'commandlineoptions'}->{'t'}) {
        print "Executing application in temporary mode\n";
        $environment->{'gpgPath'} = '/tmp/gpg';
        $environment->{'applicationData'} = '/tmp/pw7Data/'; 
        $environment->{'applicationRootData'} = '/tmp/pw7RootData/';
    } else {
    }

    if ($environment->{'commandlineoptions'}->{'h'}) {
        pw7::printUsage();
        exit 1;
    }

    if ($environment->{'commandlineoptions'}->{'v'}) {
        pw7::toggleVerbose($environment);
    }

    if ($environment->{'commandlineoptions'}->{'d'}) {
        $environment = pw7::deleteEverythingAndStartOver($environment);     
    } 
    $environment = pw7::doFileAndPermissionChecks($environment);
    
    return $environment;
}

sub changePassword {
    my $environment = $_[0] or die "Print menu called without environment\n";
    pw7::printDebug($environment, "Change password called.\n"); 
    if ($environment->{'passphraseValidated'} eq '0') {
        print "Login first (login).\n";
        return $environment;
    } elsif ($environment->{'passphraseValidated'} eq '1') {
        my $command = $environment->{'gpgPath'} . " --homedir " . $environment->{'homeKeyPath'} . " --edit-key " . $environment->{'loginName'} . "-pw7" . "\n";
        pw7::printDebug($environment, $command);
        my $session = new Expect();
        $session->spawn("$command") or die "Unable to execute command: $command";   
        if ($environment->{'verbose'} eq 'true') {
            pw7::printDebug($environment, "Setting expect.pm settings for verbose.\n");
            $session->debug(1);
            $session->log_stdout(1);    
        } else {
            $session->log_stdout(0);    
            $session->debug(0);
        }
        my $match = $session->expect(10, 
                    [qr/Command>/ =>  sub {          
                $session->send("passwd\n"), 
                            Expect::exp_continue; }],
            [qr/Enter passphrase: $/ => sub {
                $session->send($environment->{'passphrase'} . "\n")}]
        );
        $environment->{'isPasswordRotating'} = '1';
        pw7::setMyPassphrase($environment);
        pw7::printDebug($environment, "match: $match\n");  
        $match = $session->expect(10,   
            ["Enter passphrase:" => sub {
                pw7::printDebug($environment, "sending first passphrase\n");
                $session->send($environment->{'passphrase'} . "\n"),
                Expect::exp_continue;}],
            ["Repeat passphrase: " => sub {
                pw7::printDebug($environment, "Sending second passphrase\n");
                $session->send($environment->{'passphrase'} . "\n"),
                Expect::exp_continue;}],
            ["Command> " => sub {
                $session->send("quit\n"),
                Expect::exp_continue;}],
            [qr/Save changes\? \(y\/N\)/ => sub {
                print "\nSaving updated key.\n";
                $session->send("y\n"),
                Expect::exp_continue;}]
        );
        $environment->{'passphrase'} = $environment->{'password'};  
        delete $environment->{'password'};
    }   
    return $environment;
}

sub printUsage {
    print "usage: $0 [-v] pw7 command\n";
    print "\truns the pw7 interactive interpreter\n";
    print "\t-v\tverbose mode\n";
    print "\t-h\tprint this help menu and exit\n";
    print "\t-d\tdelete everything and start over\n";   
}

sub signalHandler {
        my $environment = $_[0] or die "Print menu called without environment\n";
    print "Caught signal, exiting.\n";
        $environment = pw7::unlockApplication($environment);
    Term::ReadKey::ReadMode('restore');
    exit 1;
}

sub printRegularMenu {    
    my $environment = $_[0] or die "Print menu called without environment\n"; 
    print "\nuser commands:\n"; 
    print "\t?                               Print this help\n"; 
    print "\tget <item>                      Get the password for item <title>\n";
    print "\tset <item>                      Set the password for item <title>\n";
    print "\tcreate <item>                   Create a new item <title> and set the item's password\n"; 
    print "\tauth <item>                     Change authorizations for an item\n";
    print "\tdelete <item>                   Delete an iten\n";
    print "\tpasswd                          Rotate the password for your private key\n";
    print "\tlist                            List all items\n";
    print "\ta                               Print advanced help\n";
    print "\texit                            Graceful exit\n";                                          
    return $environment;
}

sub printAdvancedMenu {
    my $environment = $_[0] or die "Print advanced menu called without environment\n";
    print "\nadvanced menu:\n";
    print "\tp                               Print the environment\n";
    print "\tlm                              List the keys in the master ring\n";  
    print "\tlh                              List the keys in your private ring\n";
    print "\tg                               Generate a private keypair\n"; 
    print "\ts                               Submit your public key to the master ring\n";
    print "\te                               Read the auth file from disk\n";   
    print "\tw                               Write the auth file to disk\n";    
    print "\tc                               Create dummy file for password validation\n";  
    print "\tt                               Toggle verbose mode\n";
    print "\thm                              Print username to hex key mappings for master database\n";
    print "\thp                              Print username to hex key mappings for private database\n";
    print "\td                               Delete all files and start over.\n";
    print "\tfc                              Check to make sure all necessary files and directories exist.\n";
    print "\tr                               Print the authorizations database\n";
    print "\tl                               Lock the application\n";
    print "\tu                               Unlock the application\n";
    print "\tcl                              Check if the application is locked\n";
    print "\twh                              Show who has the application locked\n";
    print "\tf                               Force unlock from another user.\n";
    print "\tch                              Change your login name\n";
    print "\tlogin                           Authenticate\n";
    print "\tlogout                          De-authenticate\n";
    print "\tfull                            Get full raw item\n";
    return $environment;
}

#this subroutine allows a user to change their login name to simulate multiple 
#users in the environment.  It's generally used for debug and testing.
sub changeLoginName {
    my $environment = $_[0] or die "changeLoginName called without environment\n";  
    
    print "This feature is disabled.\n";
    return $environment;

    my $userResponse;
    print "Enter your new login name: ";
    $userResponse = Term::ReadKey::ReadLine(0); 
    chomp($userResponse);
    
    if($userResponse eq $environment->{'rootKeyName'}) {
        print "Cannot change to pw7-rootcert.\n";
        return $environment;
    } else {
        pw7::printDebug($environment, "Not trying to use rootcert\n");
    }   
    if(length($userResponse) < 1) {
        print "User name must be at least one character long.\n";
        return $environment;
    } else {
        pw7::printDebug($environment, "User name is at least one character long\n");
    }
    if($userResponse=~/^[a-zA-Z0-9_-]+$/) {
        pw7::printDebug($environment, "User response passed regex validation\n");   
    } else {
        print "Login name failed regex data validation.\n";
        $environment->{'prompt'} = $environment->{'loginName'} . "\@pw7> ";
        return $environment;
    }   
    pw7::printDebug($environment,  "new login name: $userResponse\n");
    $environment = pw7::logMeOut($environment);
    $environment = undef;
    undef $environment;
    my $env;
    $env->{'version'} = $version;
    $env->{'loginName'} = $userResponse;
    $env = pw7::init($env);
    $env = pw7::initUser($env);
    $env = pw7::logMeIn($env, "Password: ");
    return $env;
}

#this subroutine returns the username of the person who has the appllication 
#locked.
sub populateLockInfo {
    my $environment = $_[0] or die "Who has locked called without environment.\n";  
    pw7::printDebug($environment, "Who has locked called.\n");  
    delete $environment->{'lockPID'};
    delete $environment->{'lockedBy'}; 
    delete $environment->{'lockedByCurrent'};
    if ($environment->{'isLocked'}) {
        my @glob = glob($environment->{'lockFilePath'} . "LOCK-*");
        if (scalar(@glob) == 1) {
            pw7::printDebug($environment, "Somebody has the application locked\n");
            my $culprit = $glob[0];
            pw7::printDebug($environment, "culprit before: $culprit\n"); 
            $culprit=~s/LOCK\-(\S+)\-(\S+)//;
            pw7::printDebug($environment, "Application locked by $1 with PID: $2\n");
            $environment->{'lockPID'} = $2; 
            $environment->{'lockedBy'} = $1;
            $environment = pw7::checkAndCleanStaleLock($environment);
            return $environment;
            if (-f $environment->{'lockFilePath'} . "LOCK-" .  $environment->{'loginName'} . "-$$") {
                $environment->{'lockedByCurrent'} = 'true';
            } else {
                $environment->{'lockedByCurrent'} = 'false';
            }   
        } else {
            print "Found a lock file that is not equal to 1. This should never happen.\n";
        }
    } else {
        pw7::printDebug($environment, "Application is not locked.\n");
        return $environment;
    }
    return $environment;
}

#this subroutine will return 1 if the application is locked, 0 if it is not.
sub checkLocked {
    my $environment = $_[0] or die "Check locked called without environment.\n";
    pw7::printDebug($environment, "Check locked called.\n");
    delete $environment->{'lockFile'};
    delete $environment->{'isLocked'};
    my @glob = glob($environment->{'lockFilePath'} . "LOCK-*");
    if (scalar(@glob) == 0) {
        pw7::printDebug($environment, "Didn't find a lock file.\n");
        $environment->{'isLocked'} = '0';   
    } elsif (scalar(@glob) > 1) {
        die "Found multiple lock files.  This should never happen.\n";
    } elsif (scalar(@glob) == 1) {
        pw7::printDebug($environment, "Found a lock file.\n");  
        $environment->{'lockFile'} = $glob[0];  
        $environment->{'isLocked'} = '1';
        $environment=pw7::populateLockInfo($environment);
    } else {
        die "Unknown error when checking if applicaiton is locked.\n";
    } 

    return $environment; 
}

#this subroutine will lock the application.  It can be called with 'l' from the
#main menu.  It's also called from a few code blocks.
sub lockApplication {
    my $environment = $_[0] or die "Lock application called without environment.\n";
    pw7::printDebug($environment, "Lock application called.\n");
    $environment = pw7::doFileAndPermissionChecks($environment);
    $environment = pw7::checkLocked($environment); 
    if ($environment->{'isLocked'}) {
        print "Application is already locked.\n";
    } else {
        pw7::printDebug($environment, "Creating: ". $environment->{'lockFilePath'} . "LOCK-" .  $environment->{'loginName'} . "-$$\n");
        my $fileName = $environment->{'lockFilePath'} . "LOCK-" .  $environment->{'loginName'} . "-$$";
        pw7::checkIfFileExistsAndCreateItIfItDoesnt($environment, $fileName);       
        $environment = pw7::checkLocked($environment);
        pw7::printDebug($environment, "Successfully locked.\n");
    }
return $environment;
}

#this unlocks the application.  It can be called with 'u' from the main
#menu and is also called from some code blocks.
sub unlockApplication {
    my $environment = $_[0] or die "Unlock application called without environment.\n";
    pw7::printDebug($environment, "Unlock application called.\n");
    if (-f $environment->{'lockFilePath'} . "LOCK-" .  $environment->{'loginName'} . "-$$") {
        pw7::printDebug($environment, "Unlocking Application.\n");
        $environment->{'fileToDelete'} = $environment->{'lockFilePath'} . "LOCK-" .  $environment->{'loginName'} . "-$$";
        pw7::checkIfFileExistsAndDeleteItIfItDoes($environment);    
        delete $environment->{'lockPID'};
        delete $environment->{'lockedBy'};
        delete $environment->{'lockFile'};
        delete $environment->{'lockedByCurrent'};
        $environment->{'isLocked'} = '0';   
        return $environment;
        pw7::printDebug($environment, "Application successfully unlocked.\n");
    } else {
        print "You have the application locked, but not with process ID $$ (you can try force unlock with 'f').\n"; 
        return $environment;
    }
    return $environment;
}

#this will force an unlock of the application.  it can only be called with 'f'
#from the main menu
sub forceUnlock {
    my $environment = $_[0] or die "Toggle verbose called without environment.\n";  
    pw7::printDebug($environment, "Force unlock called.\n");    
    $environment = pw7::checkLocked($environment);  
    if ($environment->{'isLocked'}) {   
        my @glob = glob($environment->{'lockFilePath'} . "LOCK-*");
        my $lockfile = $glob[0];
        $environment->{'fileToDelete'}=$lockfile;
        if(&yesNo($environment, "Are you sure you want to force an application unlock? This could cause data corruption.")) {
            pw7::checkIfFileExistsAndDeleteItIfItDoes($environment);
            $environment->{'isLocked'} = '0';
            delete $environment->{'lockFile'};
            delete $environment->{'lockPID'};       
            delete $environment->{'lockedBy'}; 
            delete $environment->{'lockedByCurrent'};
            pw7::printDebug($environment, "Force unlock was successful.\n");
        } else {
            print "Force unlock aborted.\n";
        }
    } else {
        print "The application is not locked.\n";
    } 
    return $environment;
}

#this sub will toggle verbose logging on and off.  It's toggled with 't' from the main menu.
sub toggleVerbose {
    my $environment = $_[0] or die "Toggle verbose called without environment.\n";
    if($environment->{'verbose'} eq 'false') {
        print "Verbose mode enabled.\n";
        $environment->{'verbose'} = 'true' ;
    } elsif ($environment->{'verbose'} eq 'true') {
        print "Verbose mode disabled.\n";
        $environment->{'verbose'} = 'false';
    }
}

#this will print the string passed to it if debug is enabled.
sub printDebug {
    my $environment = $_[0] or die "Toggle verbose called without environmen\n";    
    my $message = $_[1] or die "Print debug called without environment\n";
    if ( defined $environment->{'verbose'}) {
        if($environment->{'verbose'} eq 'true') {
            print "DEBUG: " . $message;     
        } else {
        }   
    } else {
    }
}

#this subroutine will change the authorizations for a particular item
sub authItem {
    my $environment = $_[0] or die "Auth item called without environment.\n";
    my $itemName = $environment->{'itemName'};
        
    if (!$itemName) {
        print "Pass an item name as a parameter to this command.\n";    
        return $environment;
    } else {
    
    }
    my $itemPath = $environment->{'itemsPath'} . $itemName;
    if ($environment->{'userFullyAuthenticated'} eq '0') {
        print "Login first (login) bleh\n";
        return $environment;
    }
    if(!&checkIfItemIsInList($environment, $itemName)) {
                print "Item $itemName does not exist.\n";
                return $environment;
        } elsif (!&checkIfIAmAuthorizedToAnItem($environment,$itemName)) {
                print "You are not authorized to item $itemName\n";
                return $environment;
        } elsif (&checkIfIAmAuthorizedToAnItem($environment,$itemName)) {
        my $decryptedData = $environment->{'pgp'}->decrypt(Filename => "$itemPath",Passphrase => $environment->{'passphrase'}); 
        my @metadata = split(/\n/, $decryptedData);
        my $authorizations = $metadata[0];  
        my @currentAuthorizations = split(/\, /, $authorizations);
        pw7::printDebug($environment, "authorizations from file: @currentAuthorizations\n");
        $environment->{'authorizationsFromFile'} = \@currentAuthorizations;
        my $password = $metadata[1];
        if($password) {
            $environment->{'password'}=$password;
            $environment->{'itemName'}=$itemName;
            pw7::printDebug($environment, "Successfully decrypted file: $itemPath.\n");         
            $environment = pw7::setAuth($environment); 
            @currentAuthorizations = @{$environment->{'decryptedauthorizationDataStucture'}{$itemName}};
            $password = join(',', @currentAuthorizations);  
            my $hexid;
            my @authorizedkeys;
            foreach my $userName (@currentAuthorizations) { 
                pw7::printDebug($environment, "checking for hex id: $userName\n");
                $hexid = $environment->{'usertohexid-master'}{$userName} or die "Security violation.\n";    
                push (@authorizedkeys, $hexid);
            }
            if ($environment->{'itemName'} eq 'pw7-appauth') {
                pw7::printDebug($environment, "setting authorization on application auth, changing password to string of hex keys.\n");
                $password = join(', ', @authorizedkeys);
                $environment->{'password'}=$password;
                $environment->{'authorizationsValid'} = '1';
            } else {
                pw7::printDebug($environment, "not setting authorization on application auth.\n");
                $environment = pw7::validateAuthorizations($environment);
            } 
            if ($environment->{'authorizationsValid'} eq '1') { 
                $environment->{'timestamp'} = localtime(time);
                $environment = pw7::encryptData($environment);
                delete $environment->{'timestamp'};
                $environment->{'writePath'} = $environment->{'itemsPath'};
                $environment = pw7::writeEncryptedDataToDisk($environment);        
                pw7::writeAuthorizationsTableToDisk($environment); 
                    $environment =  pw7::readAuthFileFromDisk($environment);    
                delete $environment->{'password'};
                undef $password;
                return $environment;
            } else {
                print "Authorizations could not be validated.\n";
            }
        } else {
            print "Unable to decrypt file: $itemPath. This should never happen.\n";         
        }
    } 
    return $environment;
}

sub validateAuthorizations {
    my $environment = $_[0] or die "Auth item called without environment.\n";
    my $itemName = $environment->{'itemName'}; 
    $environment->{'authorizationsValid'} = '1';    
    my @authorizationsToCheck = @{$environment->{'decryptedauthorizationDataStucture'}{$itemName}};
    my $itemPath = $environment->{'itemsPath'} . '/pw7-appauth';  
    $environment = pw7::createPGPHandler($environment);
    my $decryptedData = $environment->{'pgp'}->decrypt(Filename => "$itemPath",Passphrase => $environment->{'passphrase'});
    my @metadata = split(/\n/, $decryptedData);
    my $passwordString = $metadata[1];  
    my @validKeys = split (', ',$passwordString);
    foreach my $userName (@authorizationsToCheck) {     
        my $hexid = $environment->{'usertohexid-master'}{$userName} or die "Security violation.\n"; 
        if(grep { $_ eq $hexid } @validKeys) {      
            pw7::printDebug($environment, "The hexid $hexid is authorized to use the application.\n");  
        } else {
            die "The hexid $hexid is not authorized to use the application.\n"; 
            $environment->{'authorizationsValid'} = '1';    
        }
    }   
    return $environment;
}

#this subroutine will prompt for N/y in the form of a question with the string
#passed to it. it will return 1 if the response is affirmative, 0 if it is not  
sub yesNo {
    my $environment = $_[0] or die "yesNo called without environment\n";
    my $question = $_[1] or die "yesNo called without a question to ask\n"; 
    delete $environment->{'userResponse'};

    my $userResponse = "";
    
    while (($userResponse ne 'y') && ($userResponse ne 'n')) {
        print "$question (y/n)? ";
                $userResponse = Term::ReadKey::ReadLine(0);
        chomp($userResponse);
        if ($userResponse eq "") {
            $environment->{'prompt'} = $environment->{'loginName'}. "\@pw7> ";
            return 0;
        }
        elsif (($userResponse ne "y") && ($userResponse ne "n")) {
            print "\nEnter 'y' or 'n'\n";
            print "$question ";
                    $userResponse = Term::ReadKey::ReadLine(0);
        }
    } 
    $environment->{'prompt'} = $environment->{'loginName'}. "\@pw7> ";
    if($userResponse eq 'y') {
        return 1;
    } elsif ($userResponse eq 'n') {
        return 0;
    }
return $environment;
}

#this will create a dummy encrypted file.  It's used to test authentication for
#the user.  It's required to login.
sub createDummyEncryptedFile {
    my $environment = $_[0] or die "Create dummy encrypted file called  without environmen\n";
    my $itemName = "dummyFile";
    $environment->{'password'}="1337";  
    my $dummyFile = $environment->{'homeKeyPath'} . "/" . $itemName;
    pw7::printDebug($environment, "Dummy file: ". "$dummyFile\n");
    if(-f $dummyFile) {
        print "You already have a dummy file.\n";
        return;
    }
    $environment->{'ringIdentifier'} = "private";
    $environment = pw7::doIhaveAHexKeyMapping($environment);
    if(!$environment->{'hexKeyMapping'}) {
        print "Generate a keypair first (g).\n";
        return;
    }
    
    $environment->{'ringIdentifier'} = "master";
    $environment = pw7::doIhaveAHexKeyMapping($environment);
    if(!$environment->{'hexKeyMapping'}) {
        print "Submit your key to the ring first (s).\n";
        return;
    }
    $environment->{'itemName'} = $itemName;
    $environment->{'timestamp'} = localtime(time);      
    $environment = pw7::encryptData($environment);
    delete $environment->{'timestamp'}; 
    $environment->{'writePath'} = $environment->{'homeKeyPath'};
    $environment = pw7::writeEncryptedDataToDisk($environment);
    pw7::printDebug($environment, "Dummy file created.\n");
}

#this is to rotate the value of a password. it tests to make sure the user can
#encrypt the file before it's re-encrypted, preventing an auth file hack.
sub setItem {
    my $environment = $_[0] or die "Get item called without environmen\n";
    my $itemName = $environment->{'itemName'} or die "Set item called without environment\n";
    my $itemPath = $environment->{'itemsPath'} . "/" . $itemName;
    pw7::printDebug($environment, "set item called with item path: $itemPath\n");

    if ($environment->{'userFullyAuthenticated'} eq '0') {
        print "Login first (login).\n";
        return $environment;
    } else {

    }
    if ($environment->{'itemName'} eq 'pw7-appauth') {
        print "This is a special item that is set by the auth command.\n";  
        return $environment;
    }
    if(!&checkIfItemIsInList($environment, $itemName)) {
        print "Item $itemName does not exist.\n";
        return $environment;
    } elsif (!&checkIfIAmAuthorizedToAnItem($environment,$itemName)) {
        print "You are not authorized to item $itemName\n";
        return $environment;
    } elsif (&checkIfIAmAuthorizedToAnItem($environment,$itemName)) {
        pw7::printDebug($environment, "You are authorized to this item.\n");
        if ($environment->{'userFullyAuthenticated'} eq '1') {
            $environment->{'isPasswordRotating'} = '1';         
            $environment= pw7::getPassword($environment);       
            $environment->{'itemName'} = $itemName; 
            my $pswd = $environment->{'pgp'}->decrypt(Filename => "$itemPath",Passphrase => $environment->{'passphrase'});
            my @metadata = split(/\n/, $pswd);
            my $authorizations = $metadata[0];  
            my $password = $metadata[1];
            $environment->{'timestamp'} = $metadata[3];
            if (!$pswd) {
                pw7::printDebug($environment, "Failed decrypting old file.  This should never happen.\n");
            } else {
                pw7::printDebug($environment, "Successfully decrypted old file\n");
                $environment = pw7::encryptData($environment);
                delete $environment->{'timestamp'}; 
                $environment->{'itemName'} = $itemName;
                $environment->{'writePath'} = $environment->{'itemsPath'};
                $environment = pw7::writeEncryptedDataToDisk($environment);
            }
            pw7::printDebug($environment, "changing password from $pswd\n");
        } else {
            die "Unknown passphrasevalidated value, this should never happen\n";            
        }
    } else {
        die "Unknown error setting item\n";
    }
    return $environment;
}   

#this sub will get the value of a particular item name.
sub getItem {
    my $environment = $_[0] or die "Get item called without environment\n"; 
    pw7::printDebug($environment, "get item called with itemspath as: $environment->{'itemPath'}\n");
    pw7::printDebug($environment, "get item called with fromLoginIndicator: $environment->{'fromLoginIndicator'}\n");
    my $fromLoginIndicator = $environment->{'fromLoginIndicator'}; # "Get item called without from login indicator\n";
    my $itemsPath = $environment->{'itemPath'} or die "Get item called without items path\n"; 
    pw7::printDebug($environment, "get item called with login indicator: $fromLoginIndicator\n");
    my $itemPath;
    my $itemName;
        
    if ($environment->{'userFullyAuthenticated'} eq '0'  && $fromLoginIndicator == 0) {
        print "Login first (login).\n";
        return;
    } elsif ($fromLoginIndicator == 1) {
        pw7::printDebug($environment, "Called with fromLoginIndicator: $fromLoginIndicator.\n");
    }
    pw7::printDebug($environment, "from login indicator: $fromLoginIndicator\n");
    pw7::printDebug($environment, "get item canned with items path: ". $itemsPath . "\n");      
    if ($environment->{'itemName'}) {
        $itemName = $environment->{'itemName'} or die "Get item called without item name\n";
    } else {
        print "Pass item name in as a parameter.\n";
        return;
    }
    if ($itemsPath eq $environment->{'itemsPath'}) {
        $itemPath = $itemsPath . $itemName;
        pw7::printDebug($environment, "items path: $itemsPath\n");
        pw7::printDebug($environment, "item name : $itemName\n");   
        if(!&checkIfItemIsInList($environment, $itemName)) {
            print "Item $itemName does not exist.\n";
            return;
        }  
        if (!&checkIfIAmAuthorizedToAnItem($environment,$itemName)) {
            print "You are not authorized to this item.\n";  
            return;
        }
    } elsif ($itemsPath = $environment->{'homeKeyPath'}) {
        $itemPath = $itemsPath . "/"  . $itemName;
        pw7::printDebug($environment,  "items path: $itemsPath\n");
    } else {

        pw7::printDebug($environment, "Items path not valid.  This should never happen.\n");    
    }
    pw7::printDebug($environment, "Item path after selected: $itemPath\n");
    pw7::printDebug($environment, "Trying to decrypt $itemPath with password $environment->{'passphrase'}\n");  
    $environment = &createPGPHandler($environment);
    my $decryptedData = $environment->{'pgp'}->decrypt(Filename => "$itemPath",Passphrase => $environment->{'passphrase'});
    
    if ($environment->{'pgp'}->errstr =~ /unlock failed/) {
        pw7::printDebug($environment, "PGP error string: " . $environment->{'pgp'}->errstr . "\n"); 
        pw7::printDebug($environment, "Login failed.\n");   
    } elsif ($environment->{'pgp'}->errstr =~ /No Signature/) { #this is the result of a successful decryption 
        pw7::printDebug($environment, "PGP error string: " . $environment->{'pgp'}->errstr . "\n");
        if($fromLoginIndicator == "0") {
            my @metadata = split(/\n/, $decryptedData);
            my $authorizations = $metadata[0];  
            my $password = $metadata[1];
            my $timestamp = $metadata[3];
            if($environment->{'getFull'} eq '1') {
                print "$decryptedData\n";
                $environment->{'getFull'} = '0';
            } else {
                print "$password\n";
                
            } 
            pw7::printDebug($environment, "authorizations: $authorizations\n");
        } else {
            pw7::printDebug($environment, "Not echoing decrypted text to screen because decrypt came from login. \n");      
            pw7::printDebug($environment, "Login successful.\n");
        }
        if ($environment->{'itemName'} eq 'dummyFile') {
            pw7::printDebug($environment, "Just unlocked dummy file.\n");
            $environment->{'passphraseValidated'} = '1';    
        } else {
            pw7::printDebug($environment, "Didn't unlock dummy file.\n");
        }
    } elsif ($environment->{'pgp'}->errstr =~ /No such file or directory/) {
        die "PGP error string: No such file or directory incurred.  This should never happen.\n";    
    } elsif ($environment->{'pgp'}->errstr =~ /Need passphrase to unlock secret key/) {
        
    } elsif ($environment->{'pgp'}->errstr =~ /Can't find a secret key to decrypt message/) {
        print "Your private key can't decrypt this item.\n";
        return;
    } elsif (!$environment->{'pgp'}->errstr) {
        print "Successfully decrypted file.\n";
        if ($environment->{'itemName'} eq 'dummyFile') {
            $environment->{'passphraseValidated'} = 1;  
        } else {
            print "Didn't unlock dummy file\n";
        }
    }
    else {
        die "Unexpected PGP error string: " . $environment->{'pgp'}->errstr . "\n";
    }
}

#this will set the user's passphrase for the private key.
sub setMyPassphrase {
    my $environment = $_[0] or die "Set my passphrase called without environment\n";
    my $passwordmatched="0";
    my $passphrase="";
    my $passphraserepeat="";
    Term::ReadKey::ReadMode('noecho');
    while ( $passwordmatched eq "0" ) {
        if ($environment->{'isPasswordRotating'} eq '1') {
            print 'enter new passphrase: ';
        } else {
            print 'enter passphrase: ';
        }
        $passphrase = Term::ReadKey::ReadLine(0);
        chomp($passphrase);
        while (length($passphrase) < 8) {
            if  (length($passphrase) < 8) {
                print "\nPassphrase must be 8 characters or longer\n";
            }
            if ($environment->{'isPasswordRotating'} eq '1') {
                print "enter new passphrase: "; 
            } else {
                print "enter passphrase: ";
            }
            $passphrase = Term::ReadKey::ReadLine(0);
            chomp($passphrase);
        }
        print "\nrepeat passphrase: ";
        $passphraserepeat = Term::ReadKey::ReadLine(0);
        chomp($passphraserepeat);
        if ($passphraserepeat eq $passphrase) {
                $passwordmatched="1";       
                $environment->{'passphrase'} = $passphrase  
        } else {
            print "\npasssphrases do not match.\n";
        }
    }       
    Term::ReadKey::ReadMode('restore');
    $environment->{'prompt'} = $environment->{'loginName'} . "\@pw7> ";
} 

#this will authenticate a user by decrypting their dummy file
sub logMeIn {
    my $environment = $_[0] or die "Login called  without environment\n";
    my $dummyFile = $environment->{'homeKeyPath'} . "/" . "dummyFile";  
    pw7::printDebug($environment, "logMeIn called");
    if($environment->{'userFullyAuthenticated'} eq '1') {
        print "You are already logged in.\n";
        return $environment;
    }
    
    $environment = pw7::initUser($environment);
    if ( defined $environment->{'keyGenerateByInitUser'} ) {  
        if ($environment->{'keyGenerateByInitUser'} eq '1') {
            $environment->{'itemPath'} = $environment->{'homeKeyPath'}; 
            $environment->{'itemName'} = 'dummyFile';
            $environment->{'fromLoginIndicator'} = '1'; 
            pw7::getItem($environment); 
            $environment = pw7::appAuthInitialize($environment);
        } else {

        }
    }   
    if ($environment->{'errorLevel'} eq '0') {
        if($environment->{'userFullyAuthenticated'} eq '1') {
            if (! defined $environment->{'keyGenerateByInitUser'} ) {  
                print "You are already logged in.\n";
            } 
            return $environment;
        } elsif ($environment->{'passphraseValidated'} eq '0') {    
            Term::ReadKey::ReadMode('noecho');
            print "password: ";
            my $password = Term::ReadKey::ReadLine(0); 
            Term::ReadKey::ReadMode('restore');
            print "\n";
            chomp($password);
            $environment->{'passphrase'} = $password;
            $environment->{'itemPath'} = $environment->{'homeKeyPath'}; 
            $environment->{'itemName'} = 'dummyFile';
            $environment->{'fromLoginIndicator'} = '1'; 
            pw7::getItem($environment); 
            delete $environment->{'itemPath'};
    
            $environment->{'prompt'} = $environment->{'loginName'} . "\@pw7> "; 
        } else {

        }
        $environment = pw7::appAuthInitialize($environment);
        if ($environment->{'passphraseValidated'} eq '1') { 
            $environment = pw7::readAuthFileFromDisk($environment);
            delete $environment->{'keyGenerateByInitUser'};
            if ($environment->{'errorLevel'} eq '0') {
                
                $environment->{'itemName'} = 'dummyFile';    

                print "Login successful.\n";
            
            } else {
                print $environment->{'errorString'} . "\n";
                $environment->{'errorLevel'} = '0';
                delete $environment->{'errorString'};
            }                   
        } else {
            print "Login failed.\n";
        }
    } else {
        print "Error during user initialization: " . $environment->{'errorString'} . "\n";
        delete $environment->{'errorString'};
    }
return $environment;
}

#this will log a user out.
sub logMeOut {
    my $environment = $_[0] or die "Login called  without environment\n";
    pw7::printDebug($environment, "You're not logged in.\n");
    $environment = pw7::checkLocked($environment);
    if ($environment->{'isLocked'}) {
        if($environment->{'lockedBy'} eq $environment->{'loginName'} && $environment->{'lockedBy'} . "-$$" ) { #check if the application is locked by the current user
            $environment = pw7::unlockApplication($environment); #unlock the application if it is
            } else {
                print "This application isn't locked with you by this PID.\n";
            }
    } else {
        pw7::printDebug($environment,"The environment isn't locked.\n");
    } 
    my $loginName = $environment->{'loginName'}; 
    undef $environment;
    $environment = undef;
    my $newenvironment;
    $newenvironment->{'version'} = $version;
    $newenvironment->{'loginName'} = $loginName;    
    $newenvironment = pw7::init($newenvironment);
    print "You are now logged out.\n";
    return $newenvironment;
} 

#this will read the authorization file from disk and populate it into the authorization data structure.
sub readAuthFileFromDisk {
        my $environment = $_[0] or die "Read authorization file from disk called without environment\n";
        my %authorizations;

    if (!-f $environment->{'encryptedauthFile'}  ) {
        pw7::printDebug($environment, "Authorization file " . $environment->{'encryptedauthFile'} . " does not exist\n");
        return $environment;
    } else {
        pw7::printDebug($environment, "Authorization file " . $environment->{'encryptedauthFile'} . " exists\n");
    }
    my $filesize = -s $environment->{'encryptedauthFile'};
    if ($filesize eq 0) {
        pw7::printDebug($environment, "File  " . $environment->{'encryptedauthFile'} . "is 0 bytes, cannot load.\n");
        return $environment;
    } else {
        pw7::printDebug($environment, "File " . $environment->{'encryptedauthFile'} . " is $filesize byte(s)\n");
    }
    pw7::printDebug($environment, "file size: $filesize\n"); 
    open AUTHFILE, "<" . $environment->{'encryptedauthFile'} or die "unable to open encrypted auth file\n";
    my $encrypted_text;
    if ($environment->{'passphraseValidated'} eq '0' && ! $environment->{'keyGenerateByInitUser'} eq '1') {
        print "Login to read encrypted auth file from disk.\n";
    } else {
        pw7::printDebug($environment, "Processing encrypted authorization file from disk, this could take a minute.\n");
        $environment->{'pgp'} = undef;
        $environment = pw7::createPGPHandler($environment);
        my($pt, $valid, $sig) = $environment->{'pgp'}->decrypt(Filename => $environment->{'encryptedauthFile'} ,Passphrase => $environment->{'passphrase'});
        if($environment->{'pgp'}->errstr =~ /No Signature/ ) {
            pw7::printDebug($environment, "In this particular scenario not having a signature is considered accpetable\n");
            $environment->{'userFullyAuthenticated'} = '1';
        } elsif ($environment->{'pgp'}->errstr =~ /find a secret key to decrypt message/) { 
            $environment->{'errorString'} = "Authorization file decryption failed.  Have somebody authorize you to the pw7-authapp item.";
            $environment->{'errorLevel'} = '1';
            return $environment;
        } elsif ($environment->{'pgp'}->errstr) {
            print "Found unknown PGP error string: " . $environment->{'pgp'}->errstr . "\n"; 
            $environment->{'userFullyAuthenticated'} = '0';
        } else {
            print "No error found.\n";
            $environment->{'userFullyAuthenticated'} = '1';
        } 
        if(defined $valid or $environment->{'requiresignedauth'} eq '0') {
            if(defined $sig or $environment->{'requiresignedauth'} eq '0') {
                    my %decryptedauthorizations;
                if ($environment->{'requiresignedauth'} eq '1') {
                    my $dt = DateTime->from_epoch( epoch => $sig->timestamp);
                    print "Signing key $valid encrypted and signed authorization file last at $dt\n";
                } else {

                }   
                foreach (split(/\n/,$pt)) {
                    my @items = split("\t");    
                            my $itemName = $items[0]; 
                            chomp ($itemName);
                            shift(@items);
                    $environment->{'itemName'} = $itemName;
                        if($itemName eq "") {
                        pw7::printDebug($environment, "Found EOF\n");
                    } elsif (!&checkIfItemIsInList($environment, $itemName)) {        
                                    die "Found item $itemName in authfile but not on disk, quitting\n"
                            } else {
                                my $i=0;
                        foreach my $userName (@items) {
                                        chomp ($userName);
                                        pw7::printDebug($environment, "Checking for username $userName in hex key mapping database\n");
                            $environment->{'ringIdentifier'} = "master";
                            $environment = pw7::doIhaveAHexKeyMapping($environment);
                            if(!$environment->{'hexKeyMapping'}) {
                                die "Found username $userName in auth file " . $environment->{'authFile'} . " but does not exist in master public keyring\n";
                                        }                                  
                                }
                                $decryptedauthorizations{$itemName}=\@items; 
                    }
                            pw7::printDebug($environment, "Print adding item: \"$itemName\" with encrypted authorizations for \"" . join(', ', @items) . "\" to enrypted authorizations database in memory.\n");
                }
                $environment->{'decryptedauthorizationDataStucture'}=\%decryptedauthorizations;
            
            } else {
                die "Signature on auth file defined\n";
                return $environment;
            }

        } else {
            die "Valid is not defined.\n";
            return $environment;
        }
    }
    
        close AUTHFILE;
    return $environment;
}

#this will print the authorization data structure in memory
sub printAuthorizationsDataStructure {
        my $environment = $_[0] or die "Print authorization file from disk called without environment\n";
    if ($environment->{'userFullyAuthenticated'} eq '0') {      
        print "Login first (login).\n";
        return $environment;
    } else {
        pw7::printDebug($environment, "User is logged in\n");
    }
    $environment = pw7::readAuthFileFromDisk($environment);
    my $authorizationDataStructure = $environment->{'decryptedauthorizationDataStucture'};
        my $itemcount=0; 
    foreach my $key (keys %{$authorizationDataStructure}) {
                my @items = @{$authorizationDataStructure->{$key}};
                print "$key: " . join(', ',@items) . "\n"; 
            $itemcount++;
    }       
    print "$itemcount item(s) in the database.\n";
    return $environment;
}

#this will return 1 if the user is authorized to the item.
sub checkIfIAmAuthorizedToAnItem {
        my $environment = $_[0] or die "Check if I am authorized to an item called without environment\n";
        my $itemName = $_[1] or die "Check if I am authorized to an item called without an item name\n";
    my @authorizations = ();
    if($environment->{'decryptedauthorizationDataStucture'}{$itemName}) {   
        pw7::printDebug($environment, "Found $itemName in authorizationDataStructure\n");
        @authorizations = @{$environment->{'decryptedauthorizationDataStucture'}{$itemName}};
    } else {
        print "Item $itemName does not appear in Authorization Data Structure, this should never happen.\n";
        return;
    }
    if( grep { $_ eq $environment->{'loginName'} } @authorizations) {   
        pw7::printDebug($environment, "You are authorized to view the item, returning 1\n");    
        return 1;
    } else {
        pw7::printDebug($environment, "You are not authorized to view the item, returning 0\n"); 
        return 0;
    }
}

#this will check if a particular item is in the items list
sub checkIfItemIsInList {
        my $environment = $_[0] or die "Check if item is in list called without environment\n";
        my $itemName = $_[1] or die "Check if item is in list called without an item name\n";
    &buildItemsList($environment); #build the items list from the authorization file on disk
    if( grep { $_ eq $itemName } @{$environment->{'itemsList'}}) {
                return 1;
        } else {
                return 0;
        }
}

#this will print the environment.  It's pretty much only used for debugging.
#sub printEnvironment {                                                                            
sub printHashReference {                                                                            
        my $hash_reference = $_[0] or die "Print hash reference called without environment.\n";           
        print "---------Begin Hash Reference---------\n"; 
    for my $key (sort keys %{$hash_reference}) {                 
                printDebug($hash_reference, "key: " . $key . "\n");
        if ($key eq 'passphrase') {                    
                        if ($hash_reference->{'verbose'} eq 'true') {
                            print "$key: " . $hash_reference->{$key} . "\n";     
            } else {
                print "$key: ********\n";              
            }
        } elsif ($key eq 'decryptedauthorizationDataStucture') {                                              
            print "--Begin authorization Data Structure:--\n";
            &printAuthorizationsDataStructure($hash_reference);
            print "--End authorization Data Structure:--\n";
        } elsif ($hash_reference->{$key} =~/^HASH\(.*\)/) { 
                        print "$key: " . $hash_reference->{$key}. "\n";     
            my $sub_hash = $hash_reference->{$key};
        } else  {
                        print "$key: " . $hash_reference->{$key}. "\n";     
                }           
        } 
        print "---------End Hash Reference---------\n"; 
    return $hash_reference;
} 

#this will prompt the user for a password to encrypt and make sure it's not blank.
sub getPassword {
        my $environment = $_[0] or die "Get password input called without environment\tn";
    my $passwordsmatched = 0;
    my $password="";    
        while (! $passwordsmatched eq "1" ) {
        Term::ReadKey::ReadMode('noecho');
        if ($environment->{'isPasswordRotating'} eq '1') {
            pw7::printDebug($environment, "Password is rotating.\n");
            print "enter new password: ";
        } else { 
            pw7::printDebug($environment, "Password isn't rotating.\n");
            print "enter password: ";   
        }           
        $password = Term::ReadKey::ReadLine(0);
        chomp($password);
        while (length($password) < 1) {
            if (length($password) < 1) {
                print "\nPassword can't be blank.\n";
            }
            if ($environment->{'isPasswordRotating'} eq '1') {
                print "enter new password: ";
            } else { 
                print "enter password: ";   
            }           
            $password = Term::ReadKey::ReadLine(0);
            chomp($password);
        } 
        print "\nverify password: ";    
        my $pwdverify = Term::ReadKey::ReadLine(0);
        chomp($pwdverify);
        if (!( $password eq $pwdverify) ) {
            print "\nPasswords didn't match, please try again\n";
        } elsif ( $password eq $pwdverify ) {
            $passwordsmatched = "1";
        } else {
            die "Unknown error getting password to encrypt\n";
        }
    }
    print "\n";
    $environment->{'password'}=$password;
    $environment->{'prompt'} = $environment->{'loginName'} . "\@pw7> ";
    Term::ReadKey::ReadMode('restore');
    return $environment;
}

#this will list the master public keys in the master key ring.  It's pretty
#much only used for debugging.
sub listMasterPublicKeys {
        my $environment = $_[0] or die "List public keys called without environment\n";
        my $command = $environment->{'gpgPath'} . " --list-keys --no-default-keyring --keyring " . $environment->{'masterPublicKeyring'};  
    pw7::printDebug($environment, "listMasterPublicKeys called\n");
    pw7::printDebug($environment, "command: $command\n");
    my $listing = `$command`;
    print $listing;
}

sub checkAndCleanStaleLock {
    my $environment = $_[0] or die "IsPidValid called without environment\n";
    my $command = $environment->{'pscmd'}; 
    my $pidfound = 'false'; 
    if ($environment->{'isLocked'}) {
        foreach my $line (split(/\n/, `$command`)) {
            if ($pidfound eq 'false') {
                if ($line eq $environment->{'lockPID'}) {
                    $pidfound = 'true'  
                } else {
                        
                }  
            } else {
            }
        }
    } else {
        print "The environment is not locked, not worrying about a stale lock\n";
    }

    if ($pidfound eq 'true') {
        pw7::printDebug($environment, "Found the PID in the lock file running.\n");

    } else {
        print "WARNING: PID $$ " . "not found on system, stale lock file is being removed.\n";      
        $environment->{'fileToDelete'} = $environment->{'lockFile'};
        &checkIfFileExistsAndDeleteItIfItDoes($environment);    
        $environment->{'isLocked'} = '0';
        delete $environment->{'lockFile'};
        delete $environment->{'lockPID'};
        delete $environment->{'lockedBy'};
    }
    
    return $environment;
}

sub printPIDValidIndicator {
    my $environment = $_[0] or die "IsPidValid called without environment\n";
    $environment = pw7::cleanPID($environment);
    return $environment;
}

#this will generate keys in a particular keyring.
sub generateKeys {
    my $environment = $_[0] or die "Generate personal keys called without environment\n";    
    my $realName = $_[1] or die "Generate personal keys called without realName for key\n";
    my $password;
    my $keyring;
    my $emailAddress;
    my $identity;
    $environment = pw7::doFileAndPermissionChecks($environment); 
        
    if($realName eq $environment->{'rootKeyName'}) {
        $password = '';     
        $keyring = $environment->{'masterPublicKeyringPath'};
        $emailAddress = $realName . '@' . Sys::Hostname::hostname();
    } else {
        $environment->{'ringIdentifier'} = "master";
        $environment = pw7::doIhaveAHexKeyMapping($environment);        
        delete $environment->{'ringIdentifier'};
        if($environment->{'hexKeyMapping'}) {
            print "Found existing key mapping for " . $environment->{'loginName'} . " in " . $environment->{'masterPublicKeyring'} . ".\n";
            return; 
        }    
        $environment->{'ringIdentifier'} = "private"; 
        $environment = pw7::doIhaveAHexKeyMapping($environment);
        delete $environment->{'ringIdentifier'};
        if($environment->{'hexKeyMapping'}) {
            print "Found existing key mapping for " . $environment->{'loginName'} . " in " . $environment->{'masterPublicKeyring'} . ".\n";
            return;
        }    
        #pw7::setMyPassphrase($environment);
        $password = $environment->{'passphrase'};
        $keyring = $environment->{'homeKeyPath'}; 
        $emailAddress = $environment->{'loginName'} . "@" . $environment->{'hostname'}; 
    } 
    #my $session = new Expect(); 
    #if ($environment->{'verbose'} eq 'true') {
    #    pw7::printDebug($environment, "Setting expect.pm settings for verbose.\n");
    #    $session->debug(1);
    #    $session->log_stdout(1);    
    #} else {
    #    $session->log_stdout(0);    
    #    $session->debug(0);
    #}
    #my $command = $environment->{'gpgPath'} . " --homedir " . $keyring . " --gen-key";
    #pw7::printDebug($environment, "Executing command: " . $command . "\n");
    print "\nGenerating keys.  This could take a couple of minutes...\n";
    #$environment = pw7::createPGPHandler($environment); 
    $identity = "$realName <$emailAddress>";
    print "IDENTITY $identity\n";
    my $keychain = Crypt::OpenPGP->new;
    my($pub, $sec) = $keychain->keygen(Type => "RSA", Size => "2048", Identity => $identity, Passphrase => 'aaaaaaaa', Verbosity => '1');
    my $public_str = $pub->save;
    my $secret_str = $sec->save;
    #print "GENERATED PUBLIC KEY $pub STR $public_str\n"; 
    #print "GENERATED PUBLIC KEY $sec STR $secret_str\n"; 

    open( PUB, '>', $environment->{'homePublicKeyring'}) or die $!;
      print PUB $public_str;
    close(PUB);

    open( PRIV, '>', $environment->{'homePrivateKeyring'} ) or die $!;
      print PRIV $secret_str;
    close(PRIV);

    #die "quit generating keys";
    #$session->spawn($environment->{'gpgPath'} . " --homedir " . $keyring . " --gen-key") or die "Unable to execute command: $command";
    #my $match = $session->expect(300, 
    #            ["selection?" =>  sub {          
    #                    $session->send("\n"), 
    #                    Expect::exp_continue; }],
    #            ["What keysize do you want" => sub {                    
    #                    $session->send($environment->{'keySize'} . "\n");            
    #                    Expect::exp_continue; }],
    #            ["Key is valid for?" => sub {
    #                    $session->send($environment->{'keyValidityTimeInDays'} . "\n");
    #                    Expect::exp_continue; }],
    #            ["Key expires at" => sub {
    #                    $session->send ("y\n");  
    #        Expect::exp_continue; }],
    #    ["Key does not expire at all" => sub { 
    #                    $session->send ("y\n");  
    #                    Expect::exp_continue; }],              
    #            ["Real name:" => sub { 
    #        #I had to add the -pw7 extension to automate this because gpg requires the loginName to be 5 or more characters, i.e. dan doesn't work 
    #                    $session->send ($realName . "\n");
    #        Expect::exp_continue; }],  
    #            ["Email address:" => sub {                            
    #                    $session->send ($emailAddress . "\n"); 
    #                    Expect::exp_continue; }],
    #            ["Comment:" => sub {                     
    #                    $session->send ("pw7-keypair\n");
    #                    Expect::exp_continue; }],
    #            ["uit?" => sub { 
    #                    $session->send ("O\n"); 
    #                    Expect::exp_continue; }],        
    #            ["Enter passphrase:" => sub { 
    #                    $session->send ($password . "\n");  
    #                    Expect::exp_continue; }],           
    #            ["Repeat passphrase:" => sub {               
    #                    $session->send ($password . "\n"); 
    #                    Expect::exp_continue; }],
    #            ["trustdb created"],    
    #    ["public and secret key created and signed." => sub {
    #    }]
    #);                      
    #pw7::printDebug($environment, "Expect match: $match\n");
    #$session->soft_close();
    #undef $session;
}

#this will list all of the keys in your home keyring
sub listHomePrivateKeys {
    my $environment = $_[0] or die "List private keys called without environment\n";
    $environment = pw7::doFileAndPermissionChecks($environment);
    system ( $environment->{'gpgPath'} . " --list-keys --no-default-keyring --fingerprint --keyring " . $environment->{'homePublicKeyring'});     
}

#this will take your public key in your private keyring and add it to the master keyring
sub addPersonalPublicToMaster {
    my $environment = $_[0] or die "Add personal public to master called without environment\n";
    &doFileAndPermissionChecks($environment);
    pw7::printDebug($environment, "Add personal public to master called.\n");   
    $environment->{'ringIdentifier'} = "master";
    $environment = pw7::doIhaveAHexKeyMapping($environment);
    delete $environment->{'ringIdentifier'};    
    if ($environment->{'hexKeyMapping'}) {
        print "Found a key for you in the master ring already.\n";
        return;
    } else {
    }
    $environment->{'ringIdentifier'} = "private";
    $environment = pw7::doIhaveAHexKeyMapping($environment);
    delete $environment->{'ringIdentifier'};    
    if (!$environment->{'hexKeyMapping'}) {
        print "You need to generate a key first (g).\n";
        return;
    } else {

    }
    my $session = new Expect(); 
    if ($environment->{'verbose'} eq 'true') {
        pw7::printDebug($environment, "Setting expect.pm settings for verbose.\n");
        $session->debug(1);
        $session->log_stdout(1);    
    } else {
        $session->log_stdout(0);    
        $session->debug(0);
    }
    my $command = $environment->{'gpgPath'} . " --homedir " . $environment->{'homeKeyPath'} . " --export " . $environment->{'loginName'} . "@" . $environment->{'hostname'} . " > " . $environment->{'homeKeyPath'} . "/" . $environment->{'loginName'} . ".key";
    pw7::printDebug($environment, "spawning command: $command\n");
    $session->spawn($command) or die "Unable to execute command: $command";
    $session->soft_close();
    
    my $session2 = new Expect();
    if ($environment->{'verbose'} eq 'true') {
        pw7::printDebug($environment, "Setting expect.pm settings for verbose.\n");
        $session2->debug(1);
        $session2->log_stdout(1);   
    } else {
        $session2->log_stdout(0);   
        $session2->debug(0);
    }
    my $command2 = $environment->{'gpgPath'} . " --no-default-keyring --keyring " . $environment->{'masterPublicKeyring'} . " --import " . $environment->{'homeKeyPath'} . "/" . $environment->{'loginName'} . ".key";
    pw7::printDebug($environment, "spawning second command: $command2\n");
    $session2->spawn($command2) or die "Unable to execute command: $command2";
    $session2->soft_close();
    $environment->{'ringIdentifier'} = "master";
    pw7::initializeUserNametoHexKeyMapHashes($environment);
}

#Keep this for the future, might want to implement key rotation or expiration at some point, this might be useful
#---------------------------------------------------------------------------------------------------------------
#sub removePersonalPublicFromMaster { 
#        my $environment = $_[0] or die "Remove personal publc from  master called without envronment\n";
#        if(!&doIhaveAHexKeyMapping($environment, $environment->{'loginName'}, "master")) {
#       print "You do not have a key in the master ring.\n";
#       return;
#   } else {
#       print "Removing personal public from master.\n";
#       pw7::printDebug($environment, "master keyring: ". $environment->{'masterPublicKeyring'} . "\n");
#       system ( $environment->{'gpgPath'} . " --keyring " . $environment->{'masterPublicKeyring'} . " --delete-key " . $environment->{'loginName'} . "-pw7");
#       &initializeUserNametoHexKeyMapHashes($environment, $environment->{'masterPublicKeyringPath'}, "master");    
#       if(!&doIhaveAHexKeyMapping($environment, $environment->{'loginName'}, "master")) {
#           print "Remove successful.\n";
#       } else {
#           print "Remove failed.\n";
#       }
#   }
#}

#this will list all of the items and denote which ones you are authorized to by printing +/-
sub listItems {
        my $environment = $_[0] or die "List items called without environment\n";
        
    if ($environment->{'userFullyAuthenticated'} eq '0') {      
        print "Login first (login).\n";
        return $environment;
    } else {
        pw7::printDebug($environment, "User is logged in\n");
    }

        &buildItemsList($environment);
    $environment = pw7::readAuthFileFromDisk($environment);
    foreach my $itemName (@{$environment->{'itemsList'}}) {
                #if (!$environment->{'authorizationDataStucture'}{$itemName}) {
                if (!$environment->{'decryptedauthorizationDataStucture'}{$itemName}) {
            die"Item $itemName does not exist in authorizations data structure but found on disk.  This should never happen.\n";
            return;
        }
        if (&checkIfIAmAuthorizedToAnItem($environment,$itemName)) {
            print "+";
        } else {
            print "-";
        }
        print $itemName . "\n";     
        }
        
    if (@{$environment->{'itemsList'}} == 0 ) {
        print "No items exist.  Create one with create <item>.\n";
        return $environment;
    } else {
        print @{$environment->{'itemsList'}} . " item(s) found.\n"; 
    }   
}

#this is to create a new item.
sub newItem {
        my $environment = $_[0] or die "Create new item called without environment\n";
    my $itemName = $environment->{'itemName'};
    if ($environment->{'userFullyAuthenticated'} eq '0') {
        print "Login first (login).\n";
        return $environment;
    }
        $environment->{'ringIdentifier'} = "master";
    $environment = pw7::doIhaveAHexKeyMapping($environment);
    if (!$environment->{'hexKeyMapping'}) {
                print "Generate a key first (g)\n";
                return $environment; 
        }
        if (-f $environment->{'itemsPath'} . $itemName) {
                print "Item " . $itemName . " already exists.\n"; 
                return $environment; 
        }
        pw7::printDebug($environment, "item length:  " .  length($itemName) . "\n");
    if ($itemName=~/^[a-zA-Z0-9_-]+$/) {
        pw7::printDebug($environment, "Item name: $itemName\n");
        pw7::printDebug($environment, "Item passed regex data validation\n");
    } else {
        print "Item failed data validation due to invalid character.  Valid characters are: a-zA-Z0-9_-\n";
        return $environment;
    }
    if (length($itemName) >= $environment->{'maxItemNameLength'}) {
        print "Item name must be less than " . $environment->{'maxItemNameLength'} . " characters, your item was " . length($itemName) . " characters \n.";
        return $environment;
    }

    $environment = pw7::getPassword($environment);
        $environment = pw7::setAuth($environment); 
        $environment->{'timestamp'} = localtime(time); 
    $environment->{'itemName'} = $itemName;
        $environment = pw7::encryptData($environment);
    delete $environment->{'timestamp'};
    $environment->{'writePath'} = $environment->{'itemsPath'}; 
    $environment = pw7::writeEncryptedDataToDisk($environment);        
    &writeAuthorizationsTableToDisk($environment); 
    $environment = pw7::readAuthFileFromDisk($environment);
    return $environment;
}

sub deleteItem {
    my $environment = $_[0] or die "Create new item called without environment\n";
    my $authorizationDataStructure = $environment->{'decryptedauthorizationDataStucture'};
    my $itemName = $environment->{'itemName'};
    pw7::printDebug($environment, "delete item called\n");  
    my $keycount=0;
    for my $key (keys %{$authorizationDataStructure}) {
        $keycount+=1;
    }
    printDebug($environment, "key count: $keycount\n");

    if ($environment->{'itemName'} eq 'pw7-appauth') {
        print "This is a special item that cannot be deleted.\n";
        return $environment;
    }

    if ($environment->{'userFullyAuthenticated'} eq '0') {
        print "Login first (login).\n";
    } else {
            if (-f $environment->{'itemsPath'} . $itemName) {
                    pw7::printDebug($environment, "Item " . $itemName . " exists.\n"); 
                my $fileToUnlink = $environment->{'itemsPath'} . $itemName;
            pw7::printDebug($environment, "unlinking file: $fileToUnlink\n");
            unlink $fileToUnlink or die "Can't delete " . $fileToUnlink . ": " .  $! . "\n";    
            delete $environment->{'decryptedauthorizationDataStucture'}{$itemName};
            if($keycount == 1) {
                print "The last record was just deleted.\n";        
                delete $environment->{'decryptedauthorizationDataStucture'};
                pw7::printDebug($environment, "Unlinking authorization file\n");
                unlink $environment->{'encryptedauthFile'}; 
            } else {
                my $expectedRemaining = $keycount-1;
                pw7::printDebug($environment,"There should still be some records left.\n"); 
                &writeAuthorizationsTableToDisk($environment);
            }       

        } else {
                    print "Item " . $itemName . " does not exist.\n"; 
        }
    }

    return $environment;
}

#this will change authorizations to a particular item.
sub setAuth {
        my $environment = $_[0] or die "Set authorizations called without environment\n";
        my $itemName = $environment->{'itemName'} or die "Set authorizations called without an item name\n";
    my @authorizations;
    
    if ($environment->{'decryptedauthorizationDataStucture'}{$itemName}) {
        pw7::printDebug($environment, "Authorization for item $itemName exists in data structure already, using authorizations from decrypted entry.\n");
        my @authorizationsFromStructure = @{$environment->{'decryptedauthorizationDataStucture'}{$itemName}};
        @authorizations = @{$environment->{'authorizationsFromFile'}};
        pw7::printDebug($environment, "authorizations from structure: @authorizationsFromStructure\n");
        pw7::printDebug($environment, "authorizations from the disk: @authorizations\n"); 
        my %authorizationsFromStructure = map {$_, 1} @authorizationsFromStructure;
        my @difference = grep {!$authorizationsFromStructure {$_}} @authorizations;
        my $arraySize = scalar(@difference);            
        if ($arraySize > 0) {
            die "Possible authorization file tampering. This should never happen.\n";
        } else {
            pw7::printDebug($environment, "No difference found between authorization file and authorization stored in password file\n");
        }
    } else {
        pw7::printDebug($environment,  "Authorizations for item $itemName does not exist in data structure, defaulting to ". $environment->{'loginName'} . "\n");
        @authorizations = $environment->{'loginName'};
        $environment->{'decryptedauthorizationDataStucture'}{$itemName}=\@authorizations;
    }
    pw7::printDebug($environment, "Setting auth for item: $itemName\n");
    print "Current authorizations: " . join(', ', @{$environment->{'decryptedauthorizationDataStucture'}{$itemName}}) . "\n";   
    $environment->{'prompt'} = " auth> ";   
        while ( defined ( $_ = $environment->{'term'}->readline($environment->{'prompt'})) ) {
                (/^show/) && do {
                        $environment = pw7::setItemAuthorizations($environment, $itemName);
                        print "Current authorizations: " . $environment->{'authorizationString'} ;
                        next;
                };              
                (/^help/ || /^\?/) && do {
                        &printSetAuthHelp();    
                        next;
                };
                (/^users/ || /^list/) && do {
                        $environment->{'decryptedauthorizationDataStucture'}{$itemName}=\@authorizations;
            $environment->{'ringIdentifier'} = 'master';
            $environment->{'itemName'} = $itemName;
            $environment = pw7::listAvailableUsers($environment);
            delete $environment->{'ringIdentifier'};    
            next;
                };
                (/^\+/) && do {
                        $_ =~ s#^\+##;
                        my $addAuth = $_;
                        my $size = length($_);
            $environment->{'ringIdentifier'} = 'master';
            $environment = pw7::doIhaveAHexKeyMapping($environment);
            my $hexid = $environment->{'usertohexid-master'}{$_};
            my $authIsValid;        
            if( grep { $_ eq $addAuth } @authorizations) {
                                print "$addAuth is already in the authorization list.\n";
                        } elsif (! defined $hexid) {
                                print "$addAuth does not have a public key in the master ring.\n";
                        } else {
                my $authIsValid = 0;            
                if ($itemName eq 'pw7-appauth') {
                    $authIsValid = '1';     
                } else {
                    my $itemPath = $environment->{'itemsPath'} . '/pw7-appauth';  
                    $environment = pw7::createPGPHandler($environment);
                    my $decryptedData = $environment->{'pgp'}->decrypt(Filename => "$itemPath",Passphrase => $environment->{'passphrase'});
                    my @metadata = split(/\n/, $decryptedData);
                    my $passwordString = $metadata[1];  
                    my @validKeys = split (', ',$passwordString);
                    if(grep { $_ eq $hexid } @validKeys) {
                        $authIsValid = '1';
                    } else {
                        my $validKeys = '0';
                    }
                }
                if ($authIsValid eq '1') {
                    unshift(@authorizations, $addAuth);
                                $environment->{'decryptedauthorizationDataStucture'}{$itemName}=\@authorizations;
                } else {
                    print "User $addAuth is not authorized to use the application.\n";
                } 
            }
                        next;
                };      
                (/^\-/) && do {
            $_ =~ m#^-(\S+)#;
            print "itemName: $itemName\n";
            chomp($itemName);
            if ($itemName eq "pw7-appauth") {
                print "You can't deauthorize a user from pw7-appauth once they've been added.  This is more of a security feature than anything. \n";   
            } else {
                my $userToRemove=$1;
                my($index) = grep { $authorizations[$_] eq $1 } 0..$#authorizations;
                pw7::printDebug($environment, "authorizations before: @authorizations\n");
                pw7::printDebug($environment, "de-authing $userToRemove\n");
                            if (defined $index) {
                    pw7::printDebug($environment, "index number: $index\n");
                    $environment->{'ringIdentifier'} = "master";
                    $environment = pw7::doIhaveAHexKeyMapping($environment);
                    if ( $1 eq $environment->{'loginName'}) {
                                        print "You cannot deauthorize yourself.\n";
                                } elsif (!$environment->{'hexKeyMapping'}) {
                                        die "this should never ever happen\n";
                                } elsif (grep { $_ eq $userToRemove } @authorizations) {
                        pw7::printDebug($environment, "Found $1 at index $index, splicing from array\n");
                        pw7::printDebug($environment, "Index: " . $index . "in array: " . $authorizations[$index] . "\n");
                        splice(@authorizations, $index, 1);         
                        pw7::printDebug($environment, "authorizations look like this right after deauth: @authorizations\n");
                        $environment->{'decryptedauthorizationDataStucture'}{$itemName}=\@authorizations;
                        @authorizations = @{$environment->{'decryptedauthorizationDataStucture'}{$itemName}};
                        pw7::printDebug($environment, "authorizations after being pulled back from data structure: @authorizations\n");
                    }
                    } else {
                        print "User $userToRemove isn't authorized.\n";
                    }
            }
            next;
                }; 
                ($_ eq 't') && do {
            &toggleVerbose($environment);       
            next;   
        };
        (/^end/ || /^exit/) && do {
                        $environment->{'decryptedauthorizationDataStucture'}{$itemName}=\@authorizations;
            last;                   
                };        
                ($_ eq 'p') && do {
            $environment=pw7::printHashReference($environment); 
            next;
        };
        do {      
                        print "\nInvalid auth command (try ? for help).\n";          
                } 
        }       
        $environment = pw7::setItemAuthorizations($environment, $itemName);
        print "Encrypting item $itemName with authorizations to: " . $environment->{'authorizationString'};
    $environment->{'decryptedauthorizationDataStucture'}{$itemName} = \@authorizations;
    $environment->{'prompt'} = $environment->{'loginName'} . "\@pw7> ";
    return $environment;
}

#this will take an encrypted file and write it to disk.
sub writeEncryptedDataToDisk {
    my $environment = $_[0] or die "Write encrypted data to disk called without environment\n";
        my $itemName = $environment->{'itemName'};
    my $itemPath = $environment->{'writePath'};
    pw7::printDebug($environment, "Write encrypted data to disk called.\n");
    open CRYPTO, ">" . $itemPath . "/" . $itemName or die "Unable to open file $itemPath\n";
        print CRYPTO $environment->{'encryptedData'} or die "Unable to print to file $itemPath\n";
    close CRYPTO or die "Unable to close file $itemName\n";  
    delete  $environment->{'encryptedData'};
    return $environment;
}

#this will write the authorization table to disk.
sub writeAuthorizationsTableToDisk {
    my $environment = $_[0] or die "Write authorizations table to disk called without environment\n";
    pw7::printDebug($environment, "Write authorizations table to disk called\n");
    my $authorizationDataStructure = $environment->{'decryptedauthorizationDataStucture'};
    my $authorizationstring=''; 
    for my $key (keys %{$authorizationDataStructure}) {
        pw7::printDebug($environment, "key: $key\n");
        my @authorizations = @{$authorizationDataStructure->{$key}};
        pw7::printDebug($environment, "authorizations: @authorizations\n");
        $authorizationstring = $authorizationstring . "$key\t" . join("\t", @authorizations) . "\n";
    }   
    printDebug($environment, "full authorization string to be encrypted:\n$authorizationstring"); 
    my @recipients;
    my $loginName = $environment->{'loginName'};
    my $hexid = $environment->{'usertohexid-master'}{$loginName}; 
    for my $key (keys %{$environment->{'usertohexid-master'}}) {
        push (@recipients, $key);
    }
    $environment = pw7::buildItemsList($environment);
    if ($environment->{'userFullyAuthenticated'} eq '0' and ! $environment->{'authInit'}) {
        print "Login first (login).\n";
        return $environment;
    } elsif ($environment->{'userFullyAuthenticated'} eq '1' or $environment->{'authInit'}) {
        $environment = pw7::createPGPHandler($environment);
        $environment->{'encryptedData'} = $environment->{'pgp'}->encrypt(Armour => 1, Data => $authorizationstring , Recipients => \@recipients);
        pw7::printDebug($environment, "writing encrypted data to file: " . $environment->{'encryptedauthFile'} . "\n");
        open AUTH, ">" . $environment->{'encryptedauthFile'} or die "Open auth file for writing failed\n";
        print AUTH $environment->{'encryptedData'};
        close AUTH or die "Unable to close " . $environment->{'authFile'} . "\n";
        pw7::printDebug($environment, "Write authorization table to disk successful.\n");
        if ($environment->{'pgp'}->errstr) {
            print "Found PGP error string: ". $environment->{'pgp'}->errstr . "\n";
            return $environment;
        } else {
            pw7::printDebug($environment, "Did not find PGP error string\n");
            return $environment;
        }
    }
    return $environment;
}

#this will encrypt some data for a list of recipients.
sub encryptData {
        my $environment = $_[0] or die "Set authorizations called without environment\n";
        my $itemName = $environment->{'itemName'}; 
        pw7::printDebug($environment, "encrypting item $itemName.\n");
    my $loginName=$environment->{'loginName'};
    my @recipients;
    if ($itemName eq 'dummyFile') {
        @recipients = ($loginName);
        pw7::printDebug($environment, "Encrypting data for a dummy file.\n");
        pw7::printDebug($environment, "encrypting dummy with recipient: " . join(', ', @recipients) . "\n");
    } else {
        @recipients = @{$environment->{'decryptedauthorizationDataStucture'}{$itemName}};
        pw7::printDebug($environment, "size: " . scalar(@recipients) . "\n");
        pw7::printDebug($environment, "variable: @recipients\n");
        pw7::printDebug($environment, "Recipients reference:  " . $environment->{'decryptedauthorizationDataStucture'}{$itemName} . "\n");
        pw7::printDebug($environment, "encrypting dummy with recipients: " . join(', ', @recipients) . "\n");
    }
    pw7::printDebug($environment,  "Encrypt data for item " . $itemName . " executing with recipients: " . join(', ', @recipients) . "\n");
    $environment = pw7::createPGPHandler($environment); 
    pw7::printDebug($environment, "password to encrypt: " . $environment->{'password'} . "\n");
    my $recipientlist = join(', ', @recipients);
    $environment->{'timestamp'} = localtime(time);
    my $timestamp = $environment->{'timestamp'}; 
    pw7::printDebug($environment, "timestamp: $timestamp\n");
    my $dataToEncrypt = $recipientlist . "\n" . $environment->{'password'} . "\n" . $environment->{'timestamp'};
    pw7::printDebug($environment, "data to encrypt: $dataToEncrypt\n");
    $environment->{'encryptedData'} = $environment->{'pgp'}->encrypt(Armour => 1, Data => $dataToEncrypt , Recipients => \@recipients);       
    pw7::printDebug($environment, $environment->{'encryptedData'} . "\n");
    delete $environment->{'password'};
    return $environment;
}

#this will build the items list from disk
sub buildItemsList {
        my $environment = $_[0] or die "Build items list called without environment\n";
        my @glob;
        @glob = glob($environment->{'itemsPath'} . "*");
        foreach my $item (@glob) {
                $item =~ s/$environment->{'itemsPath'}//;
        }
        $environment->{'itemsList'} = \@glob; 
    return $environment;
}

#this will print all of the users that have a key in the master ring.
sub listAvailableUsers {
        my $environment = $_[0] or die "Print list of users with keys in the master ring called without environment\n";
    my $ringidentifier = $environment->{'ringIdentifier'} or die "Print list of users with keys in the master ring called without a ring identifier\n";
    my $itemName = $environment->{'itemName'} or die "Print list of users with keys in the master ring called without an item name\n";
    my @authorizations = @{$environment->{'decryptedauthorizationDataStucture'}{$itemName}};
    $environment->{'ringIdentifier'} = 'master';
    &initializeUserNametoHexKeyMapHashes($environment);        
    my @listOfUsers;        
        for my $key (keys %{$environment->{"usertohexid-$ringidentifier"}}) {
            push(@listOfUsers, $key);
        }
        my $index;
        foreach my $userName (@authorizations) {
            pw7::printDebug($environment, "user from authorizations: $userName\n");
            pw7::printDebug($environment, "authorizations: @authorizations\n");
            undef $index;
            my ($index) = grep { $listOfUsers[$_] eq $userName } 0..$#listOfUsers;
            pw7::printDebug($environment, "index: $index\n");
            if(defined $index) {
                pw7::printDebug($environment, "listofUsers 0: $listOfUsers[0]\n");  
                pw7::printDebug($environment, "list of users prior to slice: @listOfUsers\n");
                pw7::printDebug($environment, "user $userName authorized, slicing from list with index: $index\n");
                splice(@listOfUsers, $index, 1);
                pw7::printDebug($environment, "list of users after slice: @listOfUsers\n"); 
            } else {
                pw7::printDebug($environment, "user $userName not authorized, not slicing\n");
            }
        }
        pw7::printDebug($environment, "list of users after slice: @listOfUsers\n"); 
        if ($environment->{'itemName'} eq 'pw7-appauth') {
            printDebug($environment, "skipping authorized to use application pruning\n");
        } else {
            foreach my $userName (@listOfUsers) {       
                my $hexid = $environment->{'usertohexid-master'}{$userName} or die "Security violation.\n"; 
                my $itemPath = $environment->{'itemsPath'} . '/pw7-appauth';  
                $environment = pw7::createPGPHandler($environment);
                my $decryptedData = $environment->{'pgp'}->decrypt(Filename => "$itemPath",Passphrase => $environment->{'passphrase'});
                my @metadata = split(/\n/, $decryptedData);
                my $passwordString = $metadata[1];  
                my @validKeys = split (', ',$passwordString);
                my ($index) = grep { $validKeys[$_] eq $hexid } 0..$#validKeys;
                if (defined $index) {
                    printDebug($environment, "user $userName is authorized to use the application, splicing\n");
                } else {
                    printDebug($environment, "user $userName is not authorized to use the application.\n");
                    my ($index) = grep { $listOfUsers[$_] eq $userName } 0..$#listOfUsers;
                    splice(@listOfUsers, $index, 1);
                }   
            }
        }   

        my $arraySize = scalar(@listOfUsers);
        pw7::printDebug($environment, "array size: " . $arraySize . "\n");
        if ($arraySize eq 0) {
            print "No authorizations available.\n"; 
        } else {
            print "Available users: " . join(', ', @listOfUsers) . "\n";
        }
        return $environment;
}

#this will print the authorizations for a particular item
sub setItemAuthorizations {
    my $environment = $_[0] or die "Print authorizations called without environment\n";
    my $itemName = $_[1] or die "Print authorizations called without item name\n";
    $environment->{'authorizationString'} = undef;
    $environment->{'authorizationString'} = join(', ', @{$environment->{'decryptedauthorizationDataStucture'}{$itemName}}) . "\n";
    return $environment; 
}

#sub-menu for authorizations help
sub printSetAuthHelp {
    print "Authorization mode commands:\n";
    print "\tshow                           Display current authorizations\n";
    print "\t+<user>                        Authorize a user\n";
    print "\t-<user>                        Deauthorize a user\n";
    print "\tusers,list                     List available users\n";
    print "\tt                              Toggle verbose mode\n";
    print "\tp              Print environment\n";
    print "\tend                            Exit authorization mode and encrypt file\n";
}

#this will initialize a PGP handler.
sub createPGPHandler {
    my $environment = $_[0] or die "Create PGP handler called without environment\n";
    pw7::printDebug($environment, "createPGPHandler Called.\n");
    delete $environment->{'pgp'};
    printDebug($environment, "master public key ring: " . $environment->{'masterPublicKeyring'} . "\n");
    printDebug($environment, "home private key ring: " . $environment->{'homePrivateKeyring'} . "\n");

    $environment->{'pgp'} = new Crypt::OpenPGP(
        Compat => 'GnuPG',  
        PubRing => $environment->{'masterPublicKeyring'} ,
        SecRing => $environment->{'homePrivateKeyring'} 
    );  
    if (Crypt::OpenPGP->errstr) {
        die "pgp handler creation failed with error message: " . Crypt::OpenPGP->errstr . "\n";
    } else {
        pw7::printDebug($environment, "Cound not find an error string after creating pgp handler\n");
    }

    return $environment;
}

#this will dump keyring information, parse it, and populate some nested hash references to map the
#keys from hex values to display names.  This is used for encryption.
sub initializeUserNametoHexKeyMapHashes {
    my $environment = $_[0] or die "User name to Hex key mapper called without environment\n";
    my $ringidentifier = $environment->{'ringIdentifier'} or die "User name to Hex key mapper called without master or private indicater\n"; 
    my $hostname = $environment->{'hostname'};
    my %usertohexid; 
    my %hexidtouser;
    my $command;
    my $count=0;
    delete $environment->{"usertohexid-$ringidentifier"};
    delete $environment->{"hexidtouser-$ringidentifier"};
    
    #--with-colons
    #Print key listings delimited by colons. Note that the output will be 
    #encoded in UTF-8 regardless of any --display-charset setting. This 
    #format is useful when GnuPG is called from scripts and other programs 
    #as it is easily machine parsed. 
    if ($ringidentifier eq "master") {
        $command = $environment->{'gpgPath'} . " --homedir " . $environment->{'masterPublicKeyringPath'} . " --list-keys --with-colons 2>&1";
    } elsif ($ringidentifier eq "private") {
        $command = $environment->{'gpgPath'} . " --homedir " . $environment->{'homeKeyPath'} . " --list-keys --with-colons 2>&1";
    } else { 
        die "Invalid ring identifier\n";
    }

    pw7::printDebug($environment, "command: $command\n");
    
    foreach my $line (split(/\n/, `$command`)) {
        pw7::printDebug($environment,  "$line\n");
        #if ($line =~ /^uid:.:\d+:\d+:\S{8}(\S{8}):\d{4}-\d{2}-\d{2}:.*:.*:.*:.+<(\S+)\@$hostname?>:.*:.*:$/) {  
        if ($line =~ /^uid:.:\d+:\d+:\S{8}(\S{8}):\d{4}-\d{2}-\d{2}:.*:.*:.*:.+<(\S+)\@$hostname?>:.*:.*:$/) {  
            pw7::printDebug($environment, "loading into hash mappings: $2 : $1 \n");
            $usertohexid{$2} = $1;
            $hexidtouser{$1} = $2;
            $count+=1;
        } else {
            pw7::printDebug($environment, "line failed validation: $line\n");
        }
    }       
    pw7::printDebug($environment,"Found $count keys in ring identifier $ringidentifier\n");
    if ($count > 0) { 
        #print "assigning database\n";
        $environment->{"usertohexid-$ringidentifier"} = \%usertohexid;
        $environment->{"hexidtouser-$ringidentifier"} = \%hexidtouser;
    } else {
        pw7::printDebug($environment, "hash references empty, skipping assignment\n");
    }
    return $environment;
}

#this will print the mapping references.  It's really only used for debug.
sub printUserNametoHexKeyMappings {
    my $environment = $_[0] or die "Print user name to hex key mappings called without environment\n";
    my $ringidentifier = $_[1] or die "Print user name to key key mapping called without ring identifier\n";
    $environment->{'ringIdentifier'} = 'master';
    $environment = pw7::initializeUserNametoHexKeyMapHashes($environment);     
    $environment->{'ringIdentifier'} = 'private';
    $environment = pw7::initializeUserNametoHexKeyMapHashes($environment);     
    pw7::printDebug($environment, "Print user name to Hex Key Mappings called for ring identifier $ringidentifier\n");
    for my $key (keys %{$environment->{"usertohexid-$ringidentifier"}}) {
        print "user->hexid\@$ringidentifier: " . $key . "->" . ${$environment->{"usertohexid-$ringidentifier"}}{$key} . "\n";
    }
    for my $key (keys %{$environment->{"hexidtouser-$ringidentifier"}}) {
               print "hexid->user\@$ringidentifier: " . $key . "->" . ${$environment->{"hexidtouser-$ringidentifier"}}{$key} . "\n";
    }
}

#this needs to be enhanced for security.
sub doFileAndPermissionChecks {
        my $environment = $_[0] or die "Do file and permission checks called without environment\n";
    pw7::checkIfDirectoryExistsAndCreateItIfItDoesnt($environment, $environment->{'applicationData'});
        checkIfDirectoryExistsAndCreateItIfItDoesnt($environment, $environment->{'masterPublicKeyringPath'});
    &checkIfDirectoryExistsAndCreateItIfItDoesnt($environment, $environment->{'itemsPath'});
        &checkIfDirectoryExistsAndCreateItIfItDoesnt($environment, $environment->{'homeKeyRoot'});
        &checkIfDirectoryExistsAndCreateItIfItDoesnt($environment, $environment->{'homeKeyPath'});
        &checkIfFileExistsAndCreateItIfItDoesnt($environment, $environment->{'authFile'});
        &checkIfFileExistsAndCreateItIfItDoesnt($environment, $environment->{'encryptedauthFile'});
        &checkIfFileExistsAndCreateItIfItDoesnt($environment, $environment->{'masterPublicKeyring'});
        $environment->{'ringIdentifier'} = 'master';
    $environment = pw7::initializeUserNametoHexKeyMapHashes($environment);     
        $environment->{'ringIdentifier'} = 'private';
        $environment = pw7::initializeUserNametoHexKeyMapHashes($environment);     

    if (! -f $environment->{'gpgPath'}) {
        die "gpg binary " . $environment->{'gpgPath'} . " not found, update configuration or install binary.\n"; 
    } else {
        pw7::printDebug($environment, "gpg binary found.\n");
    } 
    return $environment;
}

#this will prompt a user to generate a keypair, submit their public key to the master ring
#and then create a dummy file that is used for authentication.
sub initUser {
    my $environment = $_[0] or die "Init user called without environment\n";
    pw7::printDebug($environment, "initUser called\n");
    $environment = pw7::checkLocked($environment);
    $environment->{'errorLevel'} = 0;
    if (!$environment->{'isLocked'}) {
        $environment = pw7::lockApplication($environment);
        $environment->{'ringIdentifier'} = 'private';
        $environment = pw7::doIhaveAHexKeyMapping($environment);
        if(!$environment->{'hexKeyMapping'}) {
                    print "You don't have a private key, generating your keypair.\n";
            pw7::generateKeys($environment, $environment->{'loginName'} . "-Pw7");
            $environment->{'keyGenerateByInitUser'} = '1';
        } else {
            pw7::printDebug($environment, "Not generating a private key, already exists.\n");
        }
        pw7::printDebug($environment, "Finished calling generateKeys from initUser\n");
        $environment->{'ringIdentifier'} = 'private';
        $environment = pw7::doIhaveAHexKeyMapping($environment);
        if ($environment->{'hexKeyMapping'}) {  
            $environment->{'ringIdentifier'} = 'master';
            $environment = pw7::doIhaveAHexKeyMapping($environment);
            if(!$environment->{'hexKeyMapping'}) {
                pw7::printDebug($environment, "Adding your private key to the master ring...\n");
                pw7::addPersonalPublicToMaster($environment);
            } else {
                
            }
        } else {
            $environment->{'errorString'} = "You chose not to generate a private key.";
            $environment->{'errorLevel'} = 1;
            $environment = pw7::unlockApplication($environment);
            return $environment;
        }
        $environment->{'ringIdentifier'} = 'private';
        $environment = pw7::doIhaveAHexKeyMapping($environment);
        if($environment->{'hexKeyMapping'}) {
            $environment->{'ringIdentifier'} = 'master';
            $environment = pw7::doIhaveAHexKeyMapping($environment);
            if($environment->{'hexKeyMapping'}) {
                my $dummyFile = $environment->{'homeKeyPath'} . "/dummyFile"; 
                if (! -f $dummyFile) {
                    pw7::printDebug($environment, "Creating dummy file.\n");            
                    pw7::createDummyEncryptedFile($environment);
                } else {
                    pw7::printDebug($environment, "Found dummy file while initializing user.\n");           
                }
            } else {
                $environment->{'errorString'} = "No key exists in the master ring.";
                $environment->{'errorLevel'} = 1;   
                $environment = pw7::unlockApplication($environment);
                return $environment;
            }
                 
        } else {
            $environment->{'errorString'} = "You do not have a key in the private ring.";
            $environment->{'errorLevel'} = 1;   
            $environment = pw7::unlockApplication($environment);
            return $environment;    
            print "You do not have a key in the private ring.\n";
        }     
        $environment = pw7::unlockApplication($environment);
    } else {
        print "Cannot init user because locked by " . $environment->{'lockedBy'} . " with PID " . $environment->{'lockPID'} . "\n";
        $environment->{'errorString'} = "Cannot init user because locked by " . $environment->{'lockedBy'} . " with PID " . $environment->{'lockPID'};
        $environment->{'errorLevel'} = 1;
        return $environment;
    }
    
    return $environment;    
}

sub appAuthInitialize {
    my $environment = $_[0] or die "appAuthInitialize called without environment\n";
    my $filesize = -s $environment->{'encryptedauthFile'};
    $environment->{'ringIdentifier'} = 'master';
    $environment = pw7::doIhaveAHexKeyMapping($environment);
    delete  $environment->{'ringIdentifier'};
    if ($environment->{'hexKeyMapping'}) {  
        pw7::printDebug($environment, "You have a key in the ring.\n");
    } else {
        pw7::printDebug($environment, "You don't have one\n");
    }
    delete $environment->{'hexKeyMapping'};

    if (!-f $environment->{'itemsPath'} . "pw7-appauth" ) {
        pw7::printDebug($environment, "Application auth file doesn't exist or is 0 bytes, creating it now.\n"); 
        my $itemName = 'pw7-appauth';   
        $environment->{'writePath'} = $environment->{'itemsPath'};
        $environment->{'itemName'} = $itemName;
        my $loginName = $environment->{'loginName'};
        my @authorizations = $loginName;
        printDebug($environment, "authorizations: @authorizations\n");
        $environment->{'password'} = $environment->{'myHexKey'};
        $environment->{'decryptedauthorizationDataStucture'}{$itemName}=\@authorizations;
        $environment->{'timestamp'} = localtime(time);
        $environment = pw7::encryptData($environment);
        delete $environment->{'timestamp'}; 
        $environment = pw7::writeEncryptedDataToDisk($environment);
        $environment->{'authInit'} = '1'; 
        $environment = pw7::writeAuthorizationsTableToDisk($environment);
        $environment->{'authInit'} = '0'; 
        $environment = pw7::readAuthFileFromDisk($environment);
    } else {
        pw7::printDebug($environment, "appauth file found.\n");
    }
    return $environment;
}


sub checkIfDirectoryExistsAndCreateItIfItDoesnt {
        my $environment = $_[0] or die "Check if directory exists and create it if it doesn't called without enviuronment\n"; 
    my $directoryName = $_[1] or die "Check if directory exists and create it if it doesn't called without environment\n";
    if (!-d $directoryName) {
                pw7::printDebug ($environment, $directoryName . " does not exist, creating it.\n");
                File::Path::mkpath $directoryName or die "Can't create " . $directoryName . ": " .  $! . "\n";         
    }
}

sub checkIfDirectoryExistsAndDeleteItIfItDoes {
    my $environment = $_[0] or die "Check if directory exists and delete it if it does called without environment\n";
    my $directoryToDelete = $_[1] or die "Check if directory exists and delete it if it does called without directory to delete\n";
    pw7::printDebug($environment, "checkIfDirectoryExistsAndDeleteItIfItDoes called.\n");
    if (-d "$directoryToDelete") {
                pw7::printDebug($environment, $directoryToDelete . " does exist, deleting it.\n");
                File::Path::rmtree($directoryToDelete, 1, 1);
    } else {
        pw7::printDebug($environment, " $directoryToDelete does not exist.\n");
    }
}

sub checkIfFileExistsAndCreateItIfItDoesnt {
    my $environment = $_[0] or die "Check if file exists and create it if it doesn't called without environment\n";
    my $fileName = $_[1] or die "Check if file exists and create it if it dosn't called without file name\n";
    pw7::printDebug($environment, "Checking for $fileName and creating it if it doesn't exist\n");
    if (!-f $_[1]) {
                pw7::printDebug($environment,  $_[0] . " does not exist, creating it as a zero byte file\n");
                open(FH,">".$fileName) or die "Can't create " . $fileName . ": " .  $! . "\n";
                close(FH);
    } else {
        pw7::printDebug($environment, "filename: $fileName exists\n");
    }
}

sub checkIfFileExistsAndDeleteItIfItDoes {
        my $environment = $_[0] or die "Check if file exists and create it if it doesn't called without environment\n";
    if (-e $environment->{'fileToDelete'}) {
        pw7::printDebug($environment, "Validating data before deleting file.\n");
        if($environment->{'fileToDelete'} =~ /^([-\w\/.]+)$/) {
            pw7::printDebug($environment, "Item passed data validation for file\n");    
            pw7::printDebug($environment, $environment->{'fileToDelete'} . " exists, unlinking it\n");
                my $fileToUnlink = $1;
            pw7::printDebug($environment, "filetounlink: $fileToUnlink\n");
            unlink $fileToUnlink or die "Can't delete " . $fileToUnlink . ": " .  $! . "\n";    
            delete $environment->{'fileToDelete'};
        } else {
            die "Path failed data validation\n";
        }   
    } else {
        print "WARNING: File does not exist: " . $environment->{'fileToDelete'} . "\n";
        delete $environment->{'fileToDelete'};
    }
    return $environment;  
}

#this will delete everything and start over.  It's really only used for debug purposes.
sub deleteEverythingAndStartOver {
    my $environment = $_[0] or die "Delete everything and start over called without environment\n"; 
    pw7::printDebug($environment, "Delete everything and start over called.\n");
    #print "This feature is disabled.\n";
    #return $environment;
    $environment = pw7::checkLocked($environment);
    if ($environment->{'isLocked'}) {
        print "Application is curretly locked by " . $environment->{'lockedBy'} . " with PID " . $environment->{'lockPID'} . ". You can force unluck with (f).\n";
        return $environment;
    } else {
        printDebug($environment,  "The applicaiton is not locked.\n");  
    }
    if(&yesNo($environment, "Are you sure you want to delete everything and start over?")){
        pw7::checkIfDirectoryExistsAndDeleteItIfItDoes($environment, $environment->{'masterPublicKeyringPath'});
        pw7::checkIfDirectoryExistsAndDeleteItIfItDoes($environment, $environment->{'homeKeyPath'});        
        pw7::checkIfDirectoryExistsAndDeleteItIfItDoes($environment, $environment->{'applicationData'});
        $environment->{'fileToDelete'} = $environment->{'authFile'}; 
        pw7::checkIfFileExistsAndDeleteItIfItDoes($environment);
        $environment->{'fileToDelete'} = $environment->{'encryptedauthFile'}; 
        pw7::checkIfFileExistsAndDeleteItIfItDoes($environment);
        $environment = pw7::logMeOut($environment);
        my $loginName = $environment->{'loginName'};
        $environment = undef;
        undef $environment;
        my $environment;
        $environment->{'version'} = $version;
        $environment->{'loginName'} = $loginName; 
        $environment = pw7::init($environment);
        return $environment;
    } else {
        print "Delete aborted.\n";
        return $environment;
    }
}

#this will check if a particular username has a key in the ring.
sub doIhaveAHexKeyMapping {
        my $environment = $_[0] or die "Do Hex Key Mapping called without environment\n";
    my $userNameToCheck = $environment->{'loginName'} or die "Does user have a hex key mapping called without a user\n";
    my $ringidentifier = $environment->{'ringIdentifier'} or die "Does user have a hex key mapping called without a ring identifier\n";
    pw7::printDebug($environment, "Do I have a Hex Key Mapping Called.\n");
    $environment->{'hexKeyMapping'} = 0;
    if ($ringidentifier eq "master") {
        pw7::initializeUserNametoHexKeyMapHashes($environment);
    } elsif ($ringidentifier eq "private") {
        pw7::initializeUserNametoHexKeyMapHashes($environment);
    } else {
        die "Invalid ring identifier: $ringidentifier\n";
    }

    if (defined $environment->{"usertohexid-$ringidentifier"}{$userNameToCheck}) {     
                $environment->{'hexKeyMapping'} = 1;
            $environment->{'myHexKey'} = $environment->{"usertohexid-$ringidentifier"}{$userNameToCheck};
    } else {
                $environment->{'hexKeyMapping'} = 0; 
        }
    delete $environment->{'ringIdentifier'};    
    return $environment;
}
