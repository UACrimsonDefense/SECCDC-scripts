#! /usr/bin/sh

if [ -z "$(docker image ls 2> /dev/null| grep ub-test )" ]; then
	echo building ubuntu
	docker image build -t ub-test:1 ./images 
	echo building arch
	docker image build -t arch-test:1 ./images 
fi

echo -e "trying on ubuntu \n"
	docker container stop quickstart-ubuntu
	docker container rm -f quickstart-ubuntu
	docker container run --name quickstart-ubuntu -v ./:/home -it ub-test:1 /bin/bash -c "/home/quickstart.sh && /bin/bash"

echo -e "trying on arch \n"
	docker container stop quickstart-arch
	docker container rm -f quickstart-arch
	docker container run --name quickstart-arch -v ./:/home -it arch-test:1 /bin/bash
