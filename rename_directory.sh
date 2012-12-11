#!/bin/sh
for i in `find * $2/`; do 
	if(file $i | grep data) then 
		./rename_images.sh $i $1 $3 $4; 
	fi; 
done;

