docker-compose down; docker-compose up -d --build

docker exec db_mcp_server python scripts/init_admin_db.py

docker-compose down; docker-compose up -d --build; docker exec db_mcp_server python scripts/init_admin_db.py

docker exec db_mcp_server python src/init_admin_db --reset-admin-password Lunz2017
