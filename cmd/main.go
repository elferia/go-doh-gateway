package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func main() {
	viper.SetEnvPrefix("doh_gateway")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	e := echo.New()
	viper.SetDefault("path", "/dns-query")
	path := viper.GetString("path")
	e.GET(path, forwardQuery)
	e.POST(path, forwardQuery)

	e.Server.ReadTimeout = viper.GetDuration("timeout.read")
	e.Server.WriteTimeout = viper.GetDuration("timeout.write")
	e.Server.IdleTimeout = viper.GetDuration("timeout.keepalive")

	ctx := context.Background()
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogLatency:   true,
		LogRequestID: true,
		LogMethod:    true,
		LogStatus:    true,
		LogURI:       true,
		LogError:     true,
		HandleError:  true, // forwards error to the global error handler, so it can decide appropriate status code
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			if v.Error == nil {
				slog.LogAttrs(ctx, slog.LevelInfo, "request",
					slog.String("request_id", v.RequestID),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.Float64("latency", v.Latency.Seconds()),
				)
			} else {
				slog.LogAttrs(ctx, slog.LevelError, "error",
					slog.String("request_id", v.RequestID),
					slog.String("method", v.Method),
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.Float64("latency", v.Latency.Seconds()),
					slog.String("err", v.Error.Error()),
				)
			}
			return nil
		},
	}))
	e.Use(middleware.RequestID())

	viper.SetDefault("resolver.host", "127.0.0.1")
	viper.SetDefault("resolver.port", "53")
	viper.SetDefault("listen.port", "1080")
	slog.LogAttrs(ctx, slog.LevelWarn, "http server stopped",
		slog.Group("main", slog.String("error",
			e.Start(fmt.Sprintf("%s:%s", viper.GetString("listen.host"), viper.GetString("listen.port"))).Error())))
}

func forwardQuery(c echo.Context) error {
	request := c.Request()
	query, err := doh.RequestToMsg(request)
	if err != nil {
		return c.String(400, err.Error())
	}

	dnsId := make([]byte, 2)
	if _, err := rand.Read(dnsId); err != nil {
		return c.String(500, err.Error())
	}
	originalId := query.Id
	query.Id = binary.BigEndian.Uint16(dnsId)
	c.Response().Header().Set(echo.HeaderXRequestID, fmt.Sprintf("%v%04x",
		c.Response().Header().Get(echo.HeaderXRequestID), query.Id))

	ctx := request.Context()
	if queryTimeout := viper.GetDuration("timeout.query"); queryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(request.Context(), queryTimeout)
		defer cancel()
	}

	var result *dns.Msg
	ch := make(chan struct{})
	go func(ch chan struct{}) {
		result, err = dns.ExchangeContext(ctx, query,
			fmt.Sprintf("%s:%s", viper.GetString("resolver.host"), viper.GetString("resolver.port")))
		ch <- struct{}{}
	}(ch)
	select {
	case <-ch:
		break
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return c.String(504, ctx.Err().Error())
		}
		return c.String(500, ctx.Err().Error())
	}

	if err != nil {
		slog.LogAttrs(request.Context(), slog.LevelError, "DNS exchange error", slog.String("err", err.Error()))
		return c.String(502, err.Error())
	}

	var ttl uint32
	if len(result.Answer) > 0 {
		ttl = result.Answer[0].Header().Ttl
		for _, answer := range result.Answer {
			ttl = min(ttl, answer.Header().Ttl)
		}
	} else if len(result.Ns) > 0 {
		if soa, ok := result.Ns[0].(*dns.SOA); ok {
			ttl = soa.Minttl
		}
	}
	c.Response().Header().Set(echo.HeaderCacheControl, fmt.Sprintf("max-age=%d", ttl))

	result.Id = originalId
	result.Compress = true
	msgBytes, err := result.Pack()
	if err != nil {
		return c.String(500, err.Error())
	}

	return c.Blob(200, "application/dns-message", msgBytes)
}
