package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

func main() {
	viper.SetEnvPrefix("doh_gateway")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	e := echo.New()
	viper.SetDefault("path", "/dns-query")
	e.GET(viper.GetString("path"), forwardQuery)
	e.POST(viper.GetString("path"), forwardQuery)

	e.Server.ReadTimeout = viper.GetDuration("timeout.read")
	e.Server.WriteTimeout = viper.GetDuration("timeout.write")
	e.Server.IdleTimeout = viper.GetDuration("timeout.keepalive")

	viper.SetDefault("listen.port", "1080")
	slog.LogAttrs(context.Background(), slog.LevelWarn, "http server stopped",
		slog.Group("main", slog.String("error",
			e.Start(fmt.Sprintf("%s:%s", viper.GetString("listen.host"), viper.GetString("listen.port"))).Error())))
}

func forwardQuery(c echo.Context) error {
	_, err := doh.RequestToMsg(c.Request())
	if err != nil {
		return c.String(400, err.Error())
	}
	return c.String(200, "Hello, World!")
}
