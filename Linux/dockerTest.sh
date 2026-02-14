#! /usr/bin/sh

if [ -z "$(docker image ls 2> /dev/null| grep ub-test )" ]; then
	echo building ubuntu
	docker build -f Dockerfile.ubuntu-test -t ubuntu-test:latest .
	# echo building arch
	docker build -f Dockerfile.arch-test -t arch-test:latest .
fi

tryDistro(){
	echo -e "trying on $1 \n"
	if [ -n "(docker container ps -a | grep $1-test)" ]; then
		docker container kill $1-test
		docker container rm -f $1-test
	fi
	docker container run --name $1-test -v ./:/home -it $1-test:latest /bin/bash -c "/home/quickstart.sh && /bin/bash"
}

	tryDistro ubuntu
	# tryDistro arch
