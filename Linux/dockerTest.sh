#! /usr/bin/sh
buildImage(){
	echo building $1
	docker build -f Dockerfile.$1-test -t $1-test:latest .
}

tryDistro(){
	echo -e "trying on $1 \n"
	if [ -n "(docker container ps -a | grep $1-test)" ]; then
		# docker container kill $1-test
		docker container rm -f $1-test
	fi
	docker container run --name $1-test -v ./:/home $isIneractive $1-test:latest /bin/bash -c "/home/quickstart.sh && /bin/bash"
}

runDistro(){
	echo $1
	buildImage $1
	tryDistro $1
}

isInteractive = "-it"

workingDistros=("ubuntu" "arch" "fedora" "alpine")

if [ -z $1 ]; then 
	echo no distro specified, trying all
	for distro in "${workingDistros[@]}"; do
		isInteractive = ""
		runDistro $distro
		read -p "press ENTER to continue"
	done
else
	runDistro $1
fi

