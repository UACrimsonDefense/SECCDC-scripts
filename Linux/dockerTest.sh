#! /usr/bin/sh
buildImage(){
	if [ -z "$(docker image ls 2> /dev/null| grep $1-test )" ]; then
		echo building $1
		docker build -f Dockerfile.$1-test -t $1-test:latest .
	fi
}

tryDistro(){
	echo -e "trying on $1 \n"
	if [ -n "(docker container ps -a | grep $1-test)" ]; then
		docker container kill $1-test
		docker container rm -f $1-test
	fi
	docker container run --name $1-test -v ./:/home -it $1-test:latest /bin/bash -c "/home/quickstart.sh && /bin/bash"
}

	buildImage ubuntu
	tryDistro ubuntu

	# tryDistro arch
