package config

type Config struct {
	Database  Database
	SecretKey string `env:"SECRET_KEY,required"`
}

type Database struct {
	Host            string `env:"DB_HOST,required"`
	Port            string `env:"DB_PORT,default=5432"`
	Username        string `env:"DB_USERNAME,required"`
	Password        string `env:"DB_PASSWORD,required"`
	Name            string `env:"DB_NAME,required"`
	MaxOpenConns    string `env:"DB_MAX_OPEN_CONNS,default=5"`
	MaxConnLifetime string `env:"DB_MAX_CONN_LIFETIME,default=10m"`
	MaxIdleLifetime string `env:"DB_MAX_IDLE_LIFETIME,default=5m"`
}
