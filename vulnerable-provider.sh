#!/bin/bash
# TODO:> corrolate access to data with permissions set for the application
#		 > add state tracking so we can roll back when drozer crashes
#		 > find a way to autonomously restart drozer, i can't kill the process but I may be able to use the monkey runner
function getProviders (){ #grab all the packages with providers that have no permissions set
	sudo drozer console connect -c "run app.provider.info -p null" | grep Package | awk -F\: '{ print $2}'
}
function getUri (){
	sudo drozer console connect -c "run app.provider.finduri $1" | grep content:\/\/
}
function isReadable(){
	sudo drozer console connect -c 'run app.provider.query '$1' --selection "_id=?" --selection-args "0"' 1>&2 > /dev/null
	[ $? -gt 127 ] && echo "[*] drozer is refusing connections..." && drozer_down="true" && exit 1
	OUT=`sudo drozer console connect -c 'run app.provider.query '$1' --selection "_id=?" --selection-args "0"' 2> /dev/null`
	CHECK=`echo $OUT | grep _id | awk -F\\n '{ print $2 }'`
	if [ "$CHECK" != "" ]
	then
		echo "...|- [+] '$1' is readable"
		echo $CHECK | awk -F3.2.1\)\  '{ print $2 }' > .columns
	fi
}
function getColumns() {
	sudo drozer console connect -c 'run app.provider.query '$1 1>&2 > /dev/null
	[ $? -gt 127 ] && echo "[*] drozer is refusing connections..." && drozer_down="true" && exit 1
	OUT=`sudo drozer console connect -c 'run app.provider.query '$1' --selection "_id=?" --selection-args "0"' 1>&2 > /dev/null`
	echo -e "[*] found some coloumns: \n"$OUT
}
function isWriteable() {
	sudo drozer console connect -c 'run app.provider.read '$1'/../../../../../system/etc/hosts' 1>&2 > /dev/null
	[ $? -gt 127 ] && echo "[*] drozer is refusing connections..." && drozer_down="true" && exit 1
	OUT=`sudo drozer console connect -c 'run app.provider.insert '$1'/ ' 2> /dev/null`
	CHECK=`echo $OUT | grep -e 'localhost' | awk -F\\n '{ print $2 }'`
}
function isFileSupport(){
	sudo drozer console connect -c 'run app.provider.read '$1'/../../../../../system/etc/hosts' 1>&2 > /dev/null
	[ $? -gt 127 ] && echo "[*] drozer is refusing connections..." && drozer_down="true" && exit 1
	OUT=`sudo drozer console connect -c 'run app.provider.read '$1'/system/etc/hosts' 2> /dev/null`
	CHECK=`echo $OUT | grep -e 'localhost' | awk -F\\n '{ print $2 }'`
	if [ "$CHECK" != "" ]
	then
		echo "...|- [+] '$1' supports files" 	
	fi
}
function isReflectable(){
	echo ""
}
function isInjectable(){
	echo ""
}
function isCompleted(){
	provider=$1
	if [ -s .completed_providers ]
	then
		CHECK=`sort -r .completed_providers | grep $provider` #need to figure out how to reverse a file
		if [ "$CHECK" != "" ] 
		then 
			echo "0" 
		else
			echo "1"
		fi
	else
		echo "1"
	fi
}
function getVulnProviders(){ 
	out_file=$1
	echo "starting vulnerability scan..."
	for provider in `getProviders` 
	do
		completed=$(isCompleted $provider)
		if [ "$completed" != "0" ] 
		then
			echo " <<< inspecting [$provider] ..."
			echo "[$provider]" >> $out_file
			uri_count=`getUri $provider | grep -ce 'content:\/\/'`
			echo "...|- [*] found $uri_count URIs in the APK, inspecting..."
			read_count=0
			file_count=0
			readable=
			fileable=
			for uri in `getUri $provider`  
			do
				echo "......| inspecting URI [$uri] ..."
				sleep 1
				out=$(isReadable $uri)
				if [ -s .columns ] #I know this is a crappy way of doing this but it works :)
				then 
					echo -e ".........| Columns retrieved from '$uri':\n"
					for i in `cat .columns | sed s/\|/\\n/g`
					do
						[ "$i" != "n" ] && echo "............| $i"
					done
					rm .columns
				fi
				[ "$out" != "" ] && echo -e $out >> $out_file && readable="true" && echo -e $out && read_count=`expr $read_count + 1`
				out=$(isFileSupport $uri)
				[ "$out" != "" ] && echo -e $out >> $out_file && fileable="true" && echo -e $out && file_count=`expr $file_count + 1`	
			done
			[ "$drozer_down" != "true" ] && echo `date`" :"$provider >> .completed_providers && echo "...[$read_count readable providers, $file_count file disclosures]" #check connection and record
			[ "$drozer_down" == "true" ] && echo  "...[*] i think drozer is down, exiting..." && exit 1
			echo ""
		else
			echo " [*] skipping [$provider] ..."
		fi
		echo ">>>"
	done
}

if [ "$#" == "1" ]
then
	drozer_down=""
	getVulnProviders $1
else
	echo " Usage: vulnerable-provider.sh [output file]"
fi
