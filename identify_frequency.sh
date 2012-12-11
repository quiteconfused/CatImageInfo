#!/bin/bash
sorted_results=`cat $1 | grep MATCHED | awk -F:\  '{ print $2 }' | sed -e 's/\ /\n/g' | sort`;
uniq_sorted_results=`cat $1 | grep MATCHED | awk -F:\  '{ print $2 }' | sed -e 's/\ /\n/g' | sort | uniq`;

for i in $uniq_sorted_results; do
	popularity=0; 
	for z in $sorted_results; do
		if [ "$i" == "$z" ]
		then
			 popularity=`expr $popularity + 1`;
		fi;
	done
	echo $popularity - $i
done
