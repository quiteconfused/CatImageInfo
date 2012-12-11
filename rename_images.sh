#!/bin/sh
input_file=$1;
destination_directory=$2;
extension=`echo $input_file | awk -F \. '{print $2}'`;
# Comment the following line out to have it not remote, and replace it with the subsequent line
result=`./postimage $input_file 0 $3 $4`; 
#result=`./postimage $input_file 0';
exit_value=0;
if(echo $result | grep \:) then
	stripped=`echo $result | awk -F \:\  '{print $2}'`;
	copyvalue=0;
	while( file "$destination_directory/$stripped-$copyvalue.$extension" ); do
		copyvalue=`expr $copyvalue + 1`;
	done;
	echo Copying $input_file to $destination_directory/$stripped-$copyvalue.$extension
	cp "$input_file" "$destination_directory/$stripped-$copyvalue.$extension";
else
	echo Failed Google Lookup on $input_file
	exit_value=1;
fi;
return $exit_value;
