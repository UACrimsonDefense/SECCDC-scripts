#! /usr/bin/sh

if [ -z "$(docker image ls 2> /dev/null| grep ub-test )" ]; then
	echo build
	docker image build -t ub-test:1 . 
fi

echo -e "trying on ubuntu \n"
	docker container rm quickstart-ubuntu
	docker container run --name quickstart-ubuntu -v ./:/home -it ub-test:1 /bin/bash -c "/home/quickstart.sh && /bin/bash"

# echo -e "trying on arch \n"
# 	docker container rm quickstart-arch
# 	docker container run --name quickstart-arch -v ./:/home -it ub-test:1 /bin/bash
