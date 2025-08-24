package help

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	DBDriver string `mapstructure:"DB_DRIVER"`
	DBSource string `mapstructure:"DB_SOURCE"`
	//ServerAddress        string        `mapstructure:"SERVER_ADDRESS"`
	TokenDuration     time.Duration `mapstructure:"TOKEN_DURATION"`
	TokenSymmetricKey string        `mapstructure:"TOKEN_SYMMETRIC_KEY"`
	//RefreshTokenDuration time.Duration `mapstructure:"REFRESH_TOKEN_DURATION"`
	RunMode            string        `mapstructure:"RUN_MODE"`
	SessionKey         string        `mapstructure:"SESSION_KEY"`
	CodeExpirationTime time.Duration `mapstructure:"CODE_EXPIRATION_TIME"`
	// For the discovery endopint
	Issuer        string `mapstructure:"ISSUER"`
	AuthEndpoint  string `mapstructure:"AUTH_ENDPOINT"`
	TokenEndpoint string `mapstructure:"TOKEN_ENDPOINT"`
	JwksEndpoint  string `mapstructure:"JWKS_ENDPOINT"`
}

func LoadConfig(path string) (config Config, err error) {

	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}
	err = viper.Unmarshal(&config)
	return
}
