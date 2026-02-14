#! /usr/bin/sh

if [ -z "$(docker image ls 2> /dev/null| grep ub-test )" ]; then
	echo building ubuntu
	docker build -f Dockerfile.ubuntu-test -t ubuntu-test:latest .
	# echo building arch
	# docker build -f Dockerfile.arch-test -t arch-test:latest .
fi

tryDistro(){
	echo -e "trying on ubuntu \n"
	if [ -n "(docker container ps -a | grep $1)" ]; then
		docker container kill quickstart-$1
		docker container rm -f quickstart-$1
	fi
	docker container run --name quickstart-$1 -v ./:/home -it $1-test:latest /bin/bash -c "/home/quickstart.sh && /bin/bash"
}

	tryDistro ubuntu
	# tryDistro arch
