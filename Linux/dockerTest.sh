#! /usr/bin/sh

if [ -z "$(docker image ls 2> /dev/null| grep ub-test )" ]; then
	echo build
	docker image build -t ub-test:1 . 
fi

docker container run -v ./:/home -it ub-test:1 /home/quickstart.sh
