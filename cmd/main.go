package main

import (
	"fmt"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

func main() {
	viper.SetEnvPrefix("doh_gateway")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	e := echo.New()
	viper.SetDefault("path", "/dns-query")
	e.GET(viper.GetString("path"), func(c echo.Context) error {
		return c.String(200, "Hello, World!")
	})

	viper.SetDefault("listen.port", "1080")
	e.Start(fmt.Sprintf("%s:%s", viper.GetString("listen.host"), viper.GetString("listen.port")))
}
