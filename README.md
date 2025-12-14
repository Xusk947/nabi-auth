# Fiber DI Server Template

This is a template for a Fiber server with dependency injection
Go tech stack
- Fiber
- UberFX
- SQLC

To run simply install and run `air`

To generate queries from `/db/queries/*.sql` run `sqlc generate` 

To create migration run `dbmate new <migration_name>`

To apply migrations run `dbmate up`

To rollback migrations run `dbmate down`

And don't forget to change `DATABASE_URL` in `.env` file

written by @Xusk947 (e.g. Aziz)