package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/labstack/echo/v4"
	"github.com/miekg/dns"
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
	request := c.Request()
	query, err := doh.RequestToMsg(request)
	if err != nil {
		return c.String(400, err.Error())
	}

	viper.SetDefault("resolver.host", "127.0.0.1")
	viper.SetDefault("resolver.port", "53")
	_, err = dns.ExchangeContext(request.Context(), query,
		fmt.Sprintf("%s:%s", viper.GetString("resolver.host"), viper.GetString("resolver.port")))
	if err != nil {
		return c.String(502, err.Error())
	}

	return c.String(200, "Hello, World!")
}
