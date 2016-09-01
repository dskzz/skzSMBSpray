# skzSMBSpray

Suprisingly good SMB password sprayer.  This engine can be used in the future for a more generic password sprayer system.

Cycles passwords first then usernames.  

Help function results:
		"\t-verbose  \t\tTurn on Verbosity (also notverbose)\n"

		"\t-stop     \t\tThis means stop on a winner\n"

		"\t-resume \t\tThis switch resumes search; Need -host*\n"

		"\t-user     \t\t[name or name1,name2,name3 default is Administrator]\n"

		"\t-user_file\t\t[username file location ]\n"

		"\t-pass     \t\t[password or pass1,pass2,pass3 ]\n"

		"\t-pass_file\t\t[password file loc; default if not given*]\n"

		"\t-pass_def\t\tKnock this switch to use default pass file*\n"

		"\t-rdelay    \t\t[seconds between requests (each user)]\n"

		"\t-cdelay    \t\t[seconds between cycles (all users)]\n"

		"\t-save    	\t\t[file to save results in]\n\n"

		"\t-sv    	    \t\t[0-3; Save file verbosity ]\n\n"

		"\tGood luck, skz\n"

		"\t* Default pass file - $PASS_DEFAULT\nYou can change that it's like the 3rd line in the source.\n"

		"\tP.S. You can send both user and user_file same with pass, pass_file\n\n";
