#!/bin/bash
minsize=$1
size=`ls -la $2 | awk '{ print $5 }'`
if [ $size > $minsize ]; then
	./postimage 0 $2
	display $2
fi
rm -rf $2
