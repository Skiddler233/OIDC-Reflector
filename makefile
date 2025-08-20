IMAGE_NAME=oidc-reflector-app
CONTAINER_NAME=oidc-reflector
PORT=80

.PHONY: build run stop clean logs shell

build:
	docker build -t $(IMAGE_NAME) .

run:
	docker run -d --env-file .env -p $(PORT):5000 --name $(CONTAINER_NAME) --rm $(IMAGE_NAME)

stop:
	docker stop $(CONTAINER_NAME) || true

clean: stop
	docker rmi $(IMAGE_NAME) || true

logs:
	docker logs -f $(CONTAINER_NAME)

shell:
	docker exec -it $(CONTAINER_NAME) /bin/sh
