# TP2 DevSecOps

This project is based on the [DVNA](https://github.com/appsecco/dvna) (Damn Vulnerable Node Application) repository, adapted for DevSecOps practices.
To run this app you can either use the Docker image or set up the application manually by following the instructions below.


### Using the Docker Image

To quickly get started, pull and run the official Docker image:

```bash
docker pull naabda92/log8100_tp2
```
### Manual Setup

#### Clone the repository

```bash
git clone https://github.com/naabda92/LOG8100_TP2
cd LOG8100_TP2

```

#### Create a vars.env File

You'll need to create a vars.env file for database configuration. Example variables:


```bash
DATABASE_URL=postgres://dvna:passw0rd@dvna_db:5432/dvna_db
POSTGRES_USER=dvna
POSTGRES_PASSWORD=passw0rd
POSTGRES_DB=dvna_db
POSTGRES_HOST=dvna_db
POSTGRES_PORT=5432
```

#### Start the Application and Database

Use docker-compose to spin up the application along with the database:

```bash
docker compose up
```

#### Access the Application

You can now access the application in your browser at:
 [http://localhost:9090](http://localhost:9090)


[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=naabda92_LOG8100_TP2)](https://sonarcloud.io/summary/new_code?id=naabda92_LOG8100_TP2)
