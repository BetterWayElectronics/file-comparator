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


my $CONSOLE=Win32::Console->new;
$CONSOLE->Title('BwE BIN Comparator');

START:

my $BwE = (colored ['bold red'], qq{
===========================================================
|            __________          __________               |
|            \\______   \\ __  _  _\\_   ____/               |
|             |    |  _//  \\/ \\/  /|  __)_                |
|             |    |   \\\\        //       \\               |
|             |______  / \\__/\\__//______  /               |
|                    \\/ BIN Comparator  \\/ v1.0           |
|        		                                  |
===========================================================\n\n});
print $BwE;

my @files=(); 

while (<*.bin>) 
{
    push (@files, $_) if (-s gt "1");
}

if ( @files <= 1 ) {
	print "There is nothing to compare...\n"; 
	goto EOF;
} 

open(F,'>', "output.txt") || die $!;

print colored ['bold red'], "Comparative Analysis\n";
print "1. Compare Offsets (Result - Filename)\n"; #
print "2. Compare Offsets MD5 (MD5 Hash - Filename)\n"; #
print "3. Double Offsets Comparison (Result 1 - Result 2 - Filename)\n"; #
print "4. Dynamic Offset MD5 Calculation (Size - MD5 - Filename)\n"; #

print colored ['bold red'], "\nStatistical Analysis\n";
print "5. Compare Offsets Entropy (log2(256)) (Entropy - Filename)\n"; #
print "6. Compare BIN Entropy (log2(256)) (Entropy - Filename)\n"; #
print "7. Compare BIN Statistics (00 Count % / FF Count % - Filename)\n"; #

print colored ['bold red'], "\nHash Analysis\n";
print "8. Obtain BIN File MD5s (MD5 Hash - Filename)\n"; #
print "9. Obtain BIN File SHA1s (SHA1 Hash - Filename)\n"; #
print "10. Obtain BIN MIME Type (MIME - Filename)\n"; #


print "\nChoose Option: "; 
my $option = <STDIN>; chomp $option; 

my $clear_screen = cls(); 
print $clear_screen;
print $BwE;

if ($option eq "1") { # Compare Offsets (Result - Filename)

print "Enter Offset: "; 
my $offset = <STDIN>; chomp $offset; 
print "Enter Length: "; 
my $length = <STDIN>; chomp $length; 

$offset = hex($offset);
$length = hex($length);

print "\n"; 

foreach my $file (@files) { ### Calculating Results... 
open(my $bin, "<", $file) or die $!; binmode $bin;

seek($bin, $offset, 0);
read($bin, my $output, $length);
$output = uc ascii_to_hex($output); 

print F "$output - $file\n";

}
close(F); 
print $clear_screen;
print $BwE;
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
}  

elsif ($option eq "2") { # Compare Offsets MD5 (MD5 Hash - Filename)


print "Enter Offset: "; 
my $offset = <STDIN>; chomp $offset; 
print "Enter Length: "; 
my $length = <STDIN>; chomp $length; 

$offset = hex($offset);
$length = hex($length);

print "\n"; 

foreach my $file (@files) { ### Calculating MD5's... 
open(my $bin, "<", $file) or die $!; binmode $bin;

seek($bin, $offset, 0);
read($bin, my $output, $length);
$output = uc ascii_to_hex($output); 

my $output_MD5 = uc md5_hex($output);

print F "$$output_MD5 - $file\n";

}
close(F); 
print $clear_screen;
print $BwE;
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
} 

elsif ($option eq "3") { # Double Offsets Comparison (Result 1 - Result 2 - Filename)

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

foreach my $file (@files) { ### Calculating Results... 
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
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
}  

elsif ($option eq "4") { # Dynamic Offset MD5 Calculation (Size - MD5 - Filename)

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

foreach my $file (@files) { ### Calculating Results... 
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
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
}  

elsif ($option eq "5") { # Compare Offsets Entropy (log2(256)) (Entropy - Filename)

print "Enter Offset: "; 
my $offset = <STDIN>; chomp $offset; 
print "Enter Length: "; 
my $length = <STDIN>; chomp $length; 

$offset = hex($offset);
$length = hex($length);

print "\n"; 

foreach my $file (@files) { ### Calculating Entropy...    
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
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
} 

elsif ($option eq "6") { # Compare BIN Entropy (log2(256)) (Entropy - Filename)

print "\n"; 

foreach my $file (@files) { ### Calculating Entropy...    

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
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
} 

elsif ($option eq "7") { # Compare Offsets Statistics (00 Count % / FF Count % - Filename)

foreach my $file (@files) { ### Calculating Results... 
open(my $bin, "<", $file) or die $!; binmode $bin;

	# Byte Counting
	use constant BLOCK_SIZE => 4*1024*1024;


	my @counts = (0) x 256;
	while (1) {  ### Counting Bytes...
	   my $rv = sysread($bin, my $buf, BLOCK_SIZE);
	   die($!) if !defined($rv);
	   last if !$rv;

	   ++$counts[$_] for unpack 'C*', $buf;
	}
	
	my $filesize = -s $bin;
	my $FFCountPercent = sprintf("%.2f",($counts[0xFF] / $filesize * 100));
	my $NullCountPercent = sprintf("%.2f",($counts[0x00] / $filesize * 100));
	print F "FF: ", $counts[0xFF], " (", $FFCountPercent, "%)", " / 00: ", $counts[0x00], " (", $NullCountPercent, "%)", " - ", $file , "\n";
	
}
close(F); 
print $clear_screen;
print $BwE;
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
} 

elsif ($option eq "8") { # Obtain BIN File MD5s (MD5 Hash - Filename)

print "\n"; 

foreach my $file (@files) { ### Calculating MD5's...    
open(my $bin, "<", $file) or die $!; binmode $bin;

my $md5sum = uc Digest::MD5->new->addfile($bin)->hexdigest; 
 
print F "$md5sum - $file\n";

}
close(F); 
print $clear_screen;
print $BwE;
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
} 

elsif ($option eq "9") { # Obtain BIN File SHA1 (SHA1 Hash - Filename)

print "\n"; 

foreach my $file (@files) { ### Calculating SHA Hash...    
open(my $bin, "<", $file) or die $!; binmode $bin;

my $SHA = uc Digest::SHA->new->addfile($bin)->hexdigest; 
 
print F "$SHA - $file\n";

}
close(F); 
print $clear_screen;
print $BwE;
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
} 

elsif ($option eq "10") { # Obtain BIN MIME Type (MIME - Filename)

foreach my $file (@files) { ### Getting MIME Type 

my $ft = File::Type->new();
my $type_1 = $ft->mime_type($file);
print F "\n$type_1 $file";

}
close(F); 
print $clear_screen;
print $BwE;
print "Mission Complete!";
my $opensysfile = system("output.txt");
goto EOF;
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

print "\n\nPress Enter to Exit... ";
while (<>) {
chomp;
last unless length;
}
