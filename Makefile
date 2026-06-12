.PHONY: build up down restart ps logs shell-attacker shell-victim shell-monitor clean demo-http

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

restart: down up

ps:
	docker compose ps

logs:
	docker compose logs -f

shell-attacker:
	docker compose exec attacker bash

shell-victim:
	docker compose exec victim-client bash

shell-monitor:
	docker compose exec monitor bash

demo-http:
	docker compose exec victim-client /opt/traffic-generator.sh

clean:
	docker compose down -v --remove-orphans
	rm -rf captures/*.pcap captures/*.pcapng 2>/dev/null || true
