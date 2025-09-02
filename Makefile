DB_URL=postgresql://root:Badalona123@localhost:5432/sso?sslmode=disable

postgres: 
	docker run --name henngeone-db --network bank-network -p 5432:5432 -e POSTGRES_USER=root -e POSTGRES_PASSWORD=Badalona123 -d postgres:12-alpine
startDB:
	docker start henngeone-db
createdb:
	docker exec -it henngeone-db createdb --username=root --owner=root sso
dropdb:
	docker exec -it henngeone-db dropdb sso
migrateup:
	migrate -path db/schema -database "$(DB_URL)" -verbose up
migratedown:
	migrate -path db/schema -database "$(DB_URL)" -verbose down
sqlc:
	sqlc generate
upgradesqlc:
	brew upgrade sqlc