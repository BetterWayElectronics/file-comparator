#!/usr/bin/perl 

use strict;
#use warnings;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Digest::SHA qw(sha1 sha512_hex sha512_base64);
use Win32::Console::ANSI;
use Term::ANSIScreen qw/:color /;
use Term::ANSIScreen qw(cls);
use Time::HiRes;
use Fcntl qw(:flock :seek);
use String::HexConvert ':all';
use Win32::Console;
use File::Copy qw(copy);
use Regexp::Assemble;
use Term::ANSIScreen qw/:color :cursor :screen :keyboard/;
use Bit::Vector;
use Smart::Comments;
use File::Type;
use File::Path qw(make_path);


my $CONSOLE=Win32::Console->new;
$CONSOLE->Title('BwE File Comparator');

START:

my $BwE = (colored ['bold red'], qq{
===========================================================
|            __________          __________               |
|            \\______   \\ __  _  _\\_   ____/               |
|             |    |  _//  \\/ \\/  /|  __)_                |
|             |    |   \\\\        //       \\               |
|             |______  / \\__/\\__//______  /               |
|                    \\/ File Comparator \\/ v1.2           |
|        		                                  |
===========================================================\n\n});
print $BwE;

print "Enter File Extension: ";
my $filetype = <STDIN>; chomp $filetype; 

my @files=(); 

if ($filetype ne "") {
	
	while (<*.$filetype>) 
	{
		push (@files, $_);
	}

} else {
	
	$filetype = "bin";

	while (<*.*>) 
	{
		push (@files, $_) if (-s gt "10");
	}

	# while (</*/*.*>) 
	# {
		# push (@files, $_) if (-s gt "10");
	# }

	# while (</*/*/*.*>) 
	# {
		# push (@files, $_) if (-s gt "10");
	# }

	# while (<*/*/*/*.*>) 
	# {
		# push (@files, $_) if (-s gt "10");
	# }

}

if ( @files <= 1 ) {
	print "There is nothing to compare...\n"; 
	goto END;
} 

my $filecount = scalar @files;

open(F,'>', "output.txt") || die $!;

print "You Will Be Comparing $filecount Files.\n\n";

print colored ['bold red'], "Comparative Analysis\n";
print "1. Compare Offsets (Hex) (Result - Filename)\n"; #
print "2. Compare Offsets (ASCII) (Result - Filename)\n"; #
print "3. Compare Offsets MD5 (MD5 Hash - Filename)\n"; #
print "4. Dual Offsets Comparison (Result 1 - Result 2 - Filename)\n"; #
print "5. Dual Offsets MD5 Comparison (MD5 Hash 1 - MD5 Hash 2 - Filename)\n"; #
print "6. Dynamic Offset MD5 Calculation (Size Header - MD5 - Filename)\n"; #

print colored ['bold red'], "\nStatistical Analysis\n";
print "7. Compare Offsets Entropy (log2(256)) (Entropy - Filename)\n"; #
print "8. Compare Offsets Statistics (00 Count % / FF Count % - Filename)\n"; #
print "9. Compare File Entropy (log2(256)) (Entropy - Filename)\n"; #
print "10. Compare File Statistics (00 Count % / FF Count % - Filename)\n"; #

print colored ['bold red'], "\nHash\n";
print "11. Obtain File MD5s (MD5 Hash - Filename)\n"; #
print "12. Obtain File SHA1s (SHA1 Hash - Filename)\n"; #

print colored ['bold red'], "\nOther\n";
print "13. Obtain MIME Types (MIME - Filename)\n"; #
print "14. Extract File By Offset (/Extracted/Hash)\n";


print "\nChoose Option: "; 
my $option = <STDIN>; chomp $option; 

my $clear_screen = cls(); 
print $clear_screen;
print $BwE;

if ($option eq "1") { # Compare Offsets (Hex) (Result - Filename)

	print "Enter Offset: "; 
	my $offset = <STDIN>; chomp $offset; 
	print "Enter Length: "; 
	my $length = <STDIN>; chomp $length; 

	$offset = hex($offset);
	$length = hex($length);

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file Results... 
		open(my $bin, "<", $file) or die $!; binmode $bin;

		seek($bin, $offset, 0);
		read($bin, my $output, $length);
		$output = uc ascii_to_hex($output); 

		print F "$output - $file\n";
	}
	close(F); 
	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";

	$offset = sprintf("%X", $offset);
	$length = sprintf("%X", $length);
	my $new_filename = "$option\_-_0x$offset\_-_0x$length\_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);

	goto EOF;
}  

elsif ($option eq "2") { # Compare Offsets (ASCII) (Result - Filename)

	print "Enter Offset: "; 
	my $offset = <STDIN>; chomp $offset; 
	print "Enter Length: "; 
	my $length = <STDIN>; chomp $length; 

	$offset = hex($offset);
	$length = hex($length);

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file Results... 
		open(my $bin, "<", $file) or die $!; binmode $bin;

		seek($bin, $offset, 0);
		read($bin, my $output, $length);
		#$output = uc ascii_to_hex($output); 

		print F "$output - $file\n";
	}
	close(F); 

	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";

	$offset = sprintf("%X", $offset);
	$length = sprintf("%X", $length);
	my $new_filename = "$option\_-_0x$offset\_-_0x$length\_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);

	goto EOF;
}  

elsif ($option eq "3") { # Compare Offsets MD5 (MD5 Hash - Filename)

	print "Enter Offset: "; 
	my $offset = <STDIN>; chomp $offset; 
	print "Enter Length: "; 
	my $length = <STDIN>; chomp $length; 

	$offset = hex($offset);
	$length = hex($length);

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file MD5... 
		open(my $bin, "<", $file) or die $!; binmode $bin;

		seek($bin, $offset, 0);
		read($bin, my $output, $length);
		$output = uc ascii_to_hex($output); 

		my $output_MD5 = uc md5_hex($output);

		print F "$output_MD5 - $file\n";
	}
	close(F); 

	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";

	$offset = sprintf("%X", $offset);
	$length = sprintf("%X", $length);
	my $new_filename = "$option\_-_0x$offset\_-_0x$length\_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);

	goto EOF;
} 

elsif ($option eq "4") { # Dual Offsets Comparison (Result 1 - Result 2 - Filename)

	print "Enter Offset 1: "; 
	my $offset = <STDIN>; chomp $offset; 
	print "Enter Length 1: "; 
	my $length = <STDIN>; chomp $length; 
	print "\nEnter Offset 2: "; 
	my $offset2 = <STDIN>; chomp $offset2; 
	print "Enter Length 2: "; 
	my $length2 = <STDIN>; chomp $length2; 

	$offset = hex($offset);
	$length = hex($length);
	$offset2 = hex($offset2);
	$length2 = hex($length2);

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file Results... 
		open(my $bin, "<", $file) or die $!; binmode $bin;

		seek($bin, $offset, 0);
		read($bin, my $output, $length);
		$output = uc ascii_to_hex($output); 

		seek($bin, $offset2, 0);
		read($bin, my $output2, $length2);
		$output2 = uc ascii_to_hex($output2); 

		print F "$output - $output2 - $file\n";

	}
	
	close(F); 

	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";

	$offset = sprintf("%X", $offset);
	$offset2 = sprintf("%X", $offset2);
	$length = sprintf("%X", $length);
	$length2 = sprintf("%X", $length2);
	my $new_filename = "$option\_-_0x$offset\_-_0x$offset2\_-_0x$length\_-_0x$length2\_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);

	goto EOF;
}  

elsif ($option eq "5") { # Dual Offsets MD5 Comparison (MD5 Hash 1 - MD5 Hash 2 - Filename)

	print "Enter Offset 1: "; 
	my $offset = <STDIN>; chomp $offset; 
	print "Enter Length 1: "; 
	my $length = <STDIN>; chomp $length; 
	print "\nEnter Offset 2: "; 
	my $offset2 = <STDIN>; chomp $offset2; 
	print "Enter Length 2: "; 
	my $length2 = <STDIN>; chomp $length2; 

	$offset = hex($offset);
	$length = hex($length);
	$offset2 = hex($offset2);
	$length2 = hex($length2);

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file Results... 
		open(my $bin, "<", $file) or die $!; binmode $bin;

		seek($bin, $offset, 0);
		read($bin, my $output, $length);
		$output = uc ascii_to_hex($output); 
		my $output_MD51 = uc md5_hex($output);

		seek($bin, $offset2, 0);
		read($bin, my $output2, $length2);
		$output2 = uc ascii_to_hex($output2); 
		my $output_MD52 = uc md5_hex($output2);

		print F "$output_MD51 - $output_MD52 - $file\n";

	}
	
	close(F); 

	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";

	$offset = sprintf("%X", $offset);
	$offset2 = sprintf("%X", $offset2);
	$length = sprintf("%X", $length);
	$length2 = sprintf("%X", $length2);
	my $new_filename = "$option\_-_0x$offset\_-_0x$offset2\_-_0x$length\_-_0x$length2\_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);

	goto EOF;
}  

elsif ($option eq "6") { # Dynamic Offset MD5 Calculation (Size Header - MD5 - Filename)

	print "Enter Length Location Offset: "; 
	my $offset = <STDIN>; chomp $offset; 
	print "\nEnter Length Location Offset Length: "; 
	my $length = <STDIN>; chomp $length; 
	print "\nEnter MD5 Area Starting Offset: "; 
	my $offset2 = <STDIN>; chomp $offset2; 

	$offset = hex($offset);
	$length = hex($length);
	$offset2 = hex($offset2);

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file Results... 
		open(my $bin, "<", $file) or die $!; binmode $bin;

		seek($bin, $offset, 0); 
		read($bin, my $DynSize, $length); 
		$DynSize = uc ascii_to_hex($DynSize);
		$DynSize = unpack "H*", reverse pack "H*", $DynSize;
		$DynSize = hex($DynSize); $DynSize = uc sprintf("%x", $DynSize);

		seek($bin, $offset2, 0); 
		read($bin, my $DynMD5, hex($DynSize));
		$DynMD5 = uc md5_hex($DynMD5);

		print F "$DynSize - $DynMD5 - $file\n";

	}
	
	close(F); 

	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";

	$offset = sprintf("%X", $offset);
	$offset2 = sprintf("%X", $offset2);
	$length = sprintf("%X", $length);
	my $new_filename = "$option\_-_0x$offset\_-_0x$length\_-_0x$offset2\_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);

	goto EOF;
}  

elsif ($option eq "7") { # Compare Offsets Entropy (log2(256)) (Entropy - Filename)

	print "Enter Offset: "; 
	my $offset = <STDIN>; chomp $offset; 
	print "Enter Length: "; 
	my $length = <STDIN>; chomp $length; 

	$offset = hex($offset);
	$length = hex($length);

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file Entropy...    
		open(my $bin, "<", $file) or die $!; binmode $bin;

		seek($bin, $offset, 0); 
		read($bin, my $range, $length);

		my %Count; my $total = 0; my $entropy = 0; 
		foreach my $char (split(//, $range)) {$Count{$char}++; $total++;}
		foreach my $char (keys %Count) {my $p = $Count{$char}/$total; $entropy += $p * log($p);}
		my $entropy_result = sprintf("%.2f", -$entropy / log 2);
		 
		print F "$entropy_result - $file\n";

	}
	
	close(F); 
	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";
	
	my $new_filename = "$option\_-_0x$offset\_-_0x$length\_-_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);
	goto EOF;
} 

elsif ($option eq "8") { # Compare Offsets Statistics (00 Count % / FF Count % - Filename)

	print "Enter Offset: "; 
	my $offset = <STDIN>; chomp $offset; 
	print "Enter Length: "; 
	my $length = <STDIN>; chomp $length; 

	$offset = hex($offset);
	$length = hex($length);

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file Results...

		open(my $bin, "<", $file) or die $!;
		binmode $bin;

		# Byte Counting
		use constant BLOCK_SIZE => 4*1024*1024;

		my @counts = (0) x 256;
		seek($bin, $offset, 0); # Move to the specified offset

		my $bytes_read = 0;
		while ($bytes_read < $length) {  ### Counting $file Bytes...
			my $read_size = ($bytes_read + BLOCK_SIZE > $length) ? $length - $bytes_read : BLOCK_SIZE;
			my $rv = sysread($bin, my $buf, $read_size);
			die($!) if !defined($rv);
			last if !$rv;

			++$counts[$_] for unpack 'C*', $buf;
			$bytes_read += $rv;
		}

		# Calculating percentages based on the read length
		my $filesize = $bytes_read;
		print "\n$file - $filesize";
		my $FFCountPercent = sprintf("%.2f", ($counts[0xFF] / $filesize * 100));
		my $NullCountPercent = sprintf("%.2f", ($counts[0x00] / $filesize * 100));
		print F "FF: ", $counts[0xFF], " (", $FFCountPercent, "%)", " / 00: ", $counts[0x00], " (", $NullCountPercent, "%)", " - ", $file , "\n";
		
	}
	close(F); 
	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";
	
	my $new_filename = "$option\_-_0x$offset\_-_0x$length\_-_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);
	goto EOF;
} 

elsif ($option eq "9") { # Compare File Entropy (log2(256)) (Entropy - Filename)

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file Entropy...    

		open(my $bin, "<", $file) or die $!; binmode $bin;
		
		my $len = -s $bin;
		my ($entropy, %t) = 0;

		# Read in file 1024 bytes at a time to create frequancy table
		while( read( $bin, my $buffer, 1024) ) {
			$t{$_}++ 
				foreach split '', $buffer;

			$buffer = '';
		}

		foreach (values %t) {
			my $p = $_/$len;
			$entropy -= $p * log $p ;
		}       
		
		my $entropy_result = $entropy / log 2;

		print F sprintf("%.2f", $entropy_result), " - $file\n";

	}
	close(F); 
	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";
	
	my $new_filename = "$option\_-_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);
	goto EOF;
} 

elsif ($option eq "10") { # Compare File Statistics (00 Count % / FF Count % - Filename)

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file Results... 
	open(my $bin, "<", $file) or die $!; binmode $bin;

		# Byte Counting
		use constant BLOCK_SIZE => 4*1024*1024;


		my @counts = (0) x 256;
		while (1) {  ### Counting $file Bytes...
		   my $rv = sysread($bin, my $buf, BLOCK_SIZE);
		   die($!) if !defined($rv);
		   last if !$rv;

		   ++$counts[$_] for unpack 'C*', $buf;
		}
		
		my $filesize = -s $bin;
		print "\n$file - $filesize";
		my $FFCountPercent = sprintf("%.2f",($counts[0xFF] / $filesize * 100));
		my $NullCountPercent = sprintf("%.2f",($counts[0x00] / $filesize * 100));
		print F "FF: ", $counts[0xFF], " (", $FFCountPercent, "%)", " / 00: ", $counts[0x00], " (", $NullCountPercent, "%)", " - ", $file , "\n";
		
	}
	close(F); 
	
	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";
	
	my $new_filename = "$option\_-_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);
	goto EOF;
} 

elsif ($option eq "11") { # Obtain File MD5s (MD5 Hash - Filename)

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file MD5...    
		open(my $bin, "<", $file) or die $!; binmode $bin;

		my $md5sum = uc Digest::MD5->new->addfile($bin)->hexdigest; 
		 
		print F "$md5sum - $file\n";

	}
	close(F); 
	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";
	
	my $new_filename = "$option\_-_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);
	goto EOF;
} 

elsif ($option eq "12") { # Obtain Files SHA1 (SHA1 Hash - Filename)

	print "\n"; 

	foreach my $file (@files) { ### Calculating $file SHA Hash...    
		open(my $bin, "<", $file) or die $!; binmode $bin;

		my $SHA = uc Digest::SHA->new->addfile($bin)->hexdigest; 
		 
		print F "$SHA - $file\n";

	}
	close(F); 
	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";
	
	my $new_filename = "$option\_-_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);
	goto EOF;
} 

elsif ($option eq "13") { # Obtain MIME Types (MIME - Filename)

	foreach my $file (@files) { ### Getting $file MIME Type

		my $ft = File::Type->new();
		my $type_1 = $ft->mime_type($file);
		print F "\n$type_1 $file";

	}
	close(F); 
	print $clear_screen;
	print $BwE;
	print "Mission Complete!\n";
	
	my $new_filename = "$option\_-_output.txt";
	rename "output.txt", $new_filename;

	my $opensysfile = system($new_filename);
	goto EOF;
}

elsif ($option eq "14") { # Extract File By Offset (/Extracted/Hash)
	
	print (colored ['bold yellow'], "Extacted data is saved as their MD5 hashes to ensure each are unique.\n\n");

	print "Enter Start Offset: ";
	my $extractoffset = <STDIN>; chomp $extractoffset;
	my $originalextractoffset = $extractoffset;
	$extractoffset = hex($extractoffset);

	print "Enter Length: ";
	my $extractlength = <STDIN>; chomp $extractlength;
	$extractlength = hex($extractlength);

	my $extract;
    my $output_directory = "Extracted/$originalextractoffset";
    unless (-e $output_directory && -d $output_directory) {
        make_path($output_directory) or die "Failed To Create Output Directory!";
    }

			
	foreach my $file (@files) {
		(my $fileminusbin = $file) =~ s/\.[^.]+$//;


		open(my $bin, "<", $file) or die $!; binmode $bin;
		
		seek($bin, $extractoffset, 0); ; 
		read($bin, my $extracteddata, $extractlength);
		#$extracteddata = uc ascii_to_hex($extracteddata); 
			
		my $offsetmd5 = uc md5_hex($extracteddata);

		print "\nExtracting from $file ...."; 
		
		my $output_file = "$output_directory/${offsetmd5}.$filetype";
		
		open($extract, '+>', $output_file) or die $!; binmode($extract);
		sysseek $extract, 0x0, SEEK_SET; syswrite ($extract, $extracteddata);
		close ($extract);
		close ($bin);

	}

	print $clear_screen;
	print $BwE;
	print "Mission Complete! All Data Saved to /Extracted/$originalextractoffset/";
	goto EOF;

}	



else {
goto END;
}

EOF:

print "\n\nGo Again? (y/n): ";

my $again = <STDIN>; chomp $again; 

if ($again ne "y") {
goto END;
} else {
print $clear_screen;
goto START;
}

END:

print "\nPress Enter to Exit... ";
while (<>) {
chomp;
last unless length;
}
