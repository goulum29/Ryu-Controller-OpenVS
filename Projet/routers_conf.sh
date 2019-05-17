#!/bin/bash
#Ajout des addresses ip sur les interface des routeurs
curl -X POST -d '{"address":"192.168.10.254/24"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"address":"192.168.20.254/24"}' http://localhost:8080/router/0000000000000002
curl -X POST -d '{"address":"192.168.30.254/24"}' http://localhost:8080/router/0000000000000003
curl -X POST -d '{"address":"192.168.13.1/24"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"address":"192.168.13.2/24"}' http://localhost:8080/router/0000000000000003
curl -X POST -d '{"address":"192.168.12.1/24"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"address":"192.168.12.2/24"}' http://localhost:8080/router/0000000000000002
curl -X POST -d '{"address":"192.168.23.1/24"}' http://localhost:8080/router/0000000000000002
curl -X POST -d '{"address":"192.168.23.2/24"}' http://localhost:8080/router/0000000000000003
#Ajout des routes SI nécéssaire
curl -X POST -d '{"destination": "192.168.30.0/24", "gateway": "192.168.12.2"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"destination": "192.168.20.0/24", "gateway": "192.168.12.2"}' http://localhost:8080/router/0000000000000001
curl -X POST -d '{"destination": "192.168.10.0/24", "gateway": "192.168.12.1"}' http://localhost:8080/router/0000000000000002
curl -X POST -d '{"destination": "192.168.30.0/24", "gateway": "192.168.23.2"}' http://localhost:8080/router/0000000000000002
curl -X POST -d '{"destination": "192.168.10.0/24", "gateway": "192.168.23.1"}' http://localhost:8080/router/0000000000000003
curl -X POST -d '{"destination": "192.168.20.0/24", "gateway": "192.168.23.1"}' http://localhost:8080/router/0000000000000003