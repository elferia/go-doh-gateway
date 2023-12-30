package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

var logLevel = new(slog.LevelVar)

func main() {
	viper.SetEnvPrefix("doh_gateway")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(h))
	viper.SetDefault("log.level", "info")
	ctx := context.Background()
	if err := logLevel.UnmarshalText([]byte(viper.GetString("log.level"))); err != nil {
		slog.LogAttrs(ctx, slog.LevelError, "failed to parse log level",
			slog.String("level", viper.GetString("log.level")),
			slog.String("err", err.Error()),
		)
	}

	e := echo.New()
	viper.SetDefault("path", "/dns-query")
	path := viper.GetString("path")
	e.GET(path, forwardQuery)
	e.POST(path, forwardQuery)

	e.Server.ReadTimeout = viper.GetDuration("timeout.read")
	e.Server.WriteTimeout = viper.GetDuration("timeout.write")
	e.Server.IdleTimeout = viper.GetDuration("timeout.keepalive")

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
		return err
	}
	originalId := query.Id
	query.Id = binary.BigEndian.Uint16(dnsId)
	hexId := fmt.Sprintf("%04x", query.Id)
	c.Response().Header().Set(echo.HeaderXRequestID, c.Response().Header().Get(echo.HeaderXRequestID)+hexId)
	ctx := request.Context()
	slog.LogAttrs(ctx, slog.LevelDebug, "request details",
		slog.String("remote_addr", request.RemoteAddr),
		slog.String("request_id", c.Response().Header().Get(echo.HeaderXRequestID)),
		slog.String("query_id", hexId),
		slog.String("name", query.Question[0].Name),
		slog.String("class/type",
			dns.ClassToString[query.Question[0].Qclass]+"/"+dns.TypeToString[query.Question[0].Qtype]),
	)

	if queryTimeout := viper.GetDuration("timeout.query"); queryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, queryTimeout)
		defer cancel()
	}

	result, err := dns.ExchangeContext(
		ctx, query, fmt.Sprintf("%s:%s", viper.GetString("resolver.host"), viper.GetString("resolver.port")))
	if err != nil {
		if err == context.DeadlineExceeded {
			slog.LogAttrs(request.Context(), slog.LevelInfo, "DNS query timeout",
				slog.String("request_id", c.Response().Header().Get(echo.HeaderXRequestID)))
		} else {
			slog.LogAttrs(request.Context(), slog.LevelWarn, "DNS exchange error", slog.String("error", err.Error()))
		}
		result = &dns.Msg{}
		result.Response = true
		result.RecursionDesired = query.RecursionDesired
		result.RecursionAvailable = true
		result.Rcode = dns.RcodeServerFailure
		result.Question = append(result.Question, query.Question[0])
		goto respond
	}

	{
		var ttl uint32
		if len(result.Answer) > 0 {
			ttl = result.Answer[0].Header().Ttl
			for _, answer := range result.Answer {
				ttl = min(ttl, answer.Header().Ttl)
			}
		} else {
			for _, Ns := range result.Ns {
				if soa, ok := Ns.(*dns.SOA); ok {
					ttl = soa.Minttl
					break
				}
			}
		}
		c.Response().Header().Set(echo.HeaderCacheControl, fmt.Sprintf("max-age=%d", ttl))
	}
respond:
	result.Id = originalId
	result.Compress = true
	msgBytes, err := result.Pack()
	if err != nil {
		return err
	}

	return c.Blob(200, "application/dns-message", msgBytes)
}
