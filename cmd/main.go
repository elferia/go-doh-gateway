package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"time"

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

	// log.levelのパース失敗もログに出すため、NewTextHandlerを先に定義する
	// するとHandlerOptions.Levelを後から変更することになる
	// そのため型はLevelではなくLevelVarの必要がある
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(h))
	viper.SetDefault("log.level", "info")
	if err := logLevel.UnmarshalText([]byte(viper.GetString("log.level"))); err != nil {
		slog.LogAttrs(context.Background(), slog.LevelError, "failed to parse log level",
			slog.String("level", viper.GetString("log.level")),
			slog.String("error", err.Error()),
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
			logger := slog.With(
				slog.String("request id", v.RequestID),
				slog.String("remote addr", c.Request().RemoteAddr),
				slog.String("method", v.Method),
				slog.String("uri", v.URI),
				slog.Int("status", v.Status),
				slog.Duration("latency", v.Latency),
			)
			if v.Error == nil {
				logger.LogAttrs(context.Background(), slog.LevelInfo, "request ok")
			} else {
				logger.LogAttrs(context.Background(), slog.LevelError, "request error", slog.Any("error", v.Error))
			}
			return nil
		},
	}))
	e.Use(middleware.RequestID())

	viper.SetDefault("resolver.host", "127.0.0.1")
	viper.SetDefault("resolver.port", 53)
	viper.SetDefault("listen.port", 1080)
	var address string
	if unixSocketPath := viper.GetString("listen.unixPath"); unixSocketPath == "" {
		address = fmt.Sprintf("%s:%d", viper.GetString("listen.host"), viper.GetInt("listen.port"))
	} else {
		listener, err := net.Listen("unix", unixSocketPath)
		if err != nil {
			slog.LogAttrs(context.Background(), slog.LevelError, "failed to listen unix socket",
				slog.String("path", unixSocketPath), slog.Any("error", err))
			os.Exit(1)
		}
		e.Listener = listener
	}
	slog.LogAttrs(context.Background(), slog.LevelError, "failed to start", slog.Any("error", e.Start(address)))
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
	c.Response().Header().Set(echo.HeaderXRequestID,
		fmt.Sprintf("%v_%04x", c.Response().Header().Get(echo.HeaderXRequestID), query.Id))

	ctx := request.Context()
	var cancel context.CancelFunc
	if queryTimeout := viper.GetDuration("timeout.query"); queryTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, queryTimeout)
		defer cancel()
	}

	ch := make(chan dnsResult)
	go func(query *dns.Msg) {
		result, rtt, err := (&dns.Client{}).ExchangeContext(
			ctx, query, fmt.Sprintf("%s:%d", viper.GetString("resolver.host"), viper.GetInt("resolver.port")))
		ch <- dnsResult{Result: result, RTT: rtt, Err: err}
	}(query.Copy()) // queryは以下でもアクセスするので、raceを避けるためにコピーしてgoroutineの引数に渡している

	logger := slog.With(
		slog.String("request_id", c.Response().Header().Get(echo.HeaderXRequestID)),
		slog.String("name", query.Question[0].Name),
		slog.String("class", dns.ClassToString[query.Question[0].Qclass]),
		slog.String("type", dns.TypeToString[query.Question[0].Qtype]),
	)

	var dnsResponse *dns.Msg
	select {
	case <-ctx.Done():
		if cancel != nil {
			cancel()
		}
		if err := ctx.Err(); err == context.DeadlineExceeded {
			logger.LogAttrs(request.Context(), slog.LevelInfo, "DNS query timeout")
			dnsResponse = servfail(query)
			goto respondHttp
		} else {
			logger.LogAttrs(request.Context(), slog.LevelInfo, "request canceled", slog.Any("error", err))
			return c.NoContent(400)
		}
	case result := <-ch:
		if cancel != nil {
			cancel()
		}
		ctx = request.Context()
		if result.Err != nil {
			logger.LogAttrs(ctx, slog.LevelWarn, "DNS exchange error", slog.Any("error", result.Err))
			dnsResponse = servfail(query)
			goto respondHttp
		} else {
			dnsResponse = result.Result
			logger.LogAttrs(ctx, slog.LevelDebug, "DNS exchange ok", slog.Duration("RTT", result.RTT))
		}
	}

	if dnsResponse.Truncated {
		logger.LogAttrs(ctx, slog.LevelWarn, "DNS response truncated")
	}

	{
		var ttl uint32
		if len(dnsResponse.Answer) > 0 {
			ttl = math.MaxUint32
			for _, answer := range dnsResponse.Answer {
				ttl = min(ttl, answer.Header().Ttl)
			}
		} else {
			for _, Ns := range dnsResponse.Ns {
				if soa, ok := Ns.(*dns.SOA); ok {
					ttl = soa.Minttl
					break
				}
			}
		}
		c.Response().Header().Set(echo.HeaderCacheControl, fmt.Sprintf("max-age=%d", ttl))
	}
respondHttp:
	dnsResponse.Id = originalId
	dnsResponse.Compress = true
	responseBody, err := dnsResponse.Pack()
	if err != nil {
		return err
	}

	return c.Blob(200, "application/dns-message", responseBody)
}

type dnsResult struct {
	Result *dns.Msg
	RTT    time.Duration
	Err    error
}

func servfail(query *dns.Msg) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response:           true,
			RecursionDesired:   query.RecursionDesired,
			RecursionAvailable: true,
			Rcode:              dns.RcodeServerFailure,
		},
		Question: []dns.Question{
			query.Question[0],
		},
	}
}
