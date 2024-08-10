package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"github.com/tg123/go-htpasswd"
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
	logLevelSetting := viper.GetString("log.level")
	if err := logLevel.UnmarshalText([]byte(logLevelSetting)); err != nil {
		slog.LogAttrs(context.Background(), slog.LevelWarn, "failed to parse log level",
			slog.String("level", logLevelSetting), slog.Any("error", err))
	}

	e := echo.New()
	viper.SetDefault("path", "/dns-query")
	path := viper.GetString("path")
	e.GET(path, forwardQuery)
	e.POST(path, forwardQuery)

	e.Server.ReadTimeout = viper.GetDuration("timeout.read")
	e.Server.WriteTimeout = viper.GetDuration("timeout.write")
	e.Server.IdleTimeout = viper.GetDuration("timeout.keepalive")

	var credStore *htpasswd.File
	if authFilePath := viper.GetString("auth.path"); authFilePath != "" {
		var err error
		credStore, err = htpasswd.New(authFilePath, htpasswd.DefaultSystems, nil)
		if err != nil {
			slog.LogAttrs(context.Background(), slog.LevelError, "failed to parse password file",
				slog.String("path", authFilePath), slog.Any("error", err))
			os.Exit(1)
		}
	}
	if credStore != nil {
		e.Use(middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
			// credStoreはconcurrency safe
			return credStore.Match(username, password), nil
		}))
	}

	origIPExtractor := e.IPExtractor
	e.IPExtractor = func(request *http.Request) string {
		if v := request.Header.Get("CF-Connecting-IP"); v != "" {
			return v
		}
		return origIPExtractor(request)
	}

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
				slog.String("request_id", v.RequestID),
				slog.String("remote_addr", c.RealIP()),
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

	requestId := c.Response().Header().Get(echo.HeaderXRequestID)
	// request IDの末尾3文字をbase52 decodeしてquery IDとする
	// endianは気にしない
	tail3int := base52Decode(requestId[32-3:])
	originalId := query.Id
	query.Id = uint16(tail3int % (1 << 16))

	logger := slog.With(slog.String("request_id", requestId))
	ctx := request.Context()
	logger.LogAttrs(
		ctx, slog.LevelDebug, "query ID generated", slog.Any("tail3", tail3int), slog.Any("ID", myUint16(query.Id)))
	logger.LogAttrs(ctx, slog.LevelDebug, "request", slog.Any("headers", request.Header))

	var cancel context.CancelFunc
	if queryTimeout := viper.GetDuration("timeout.query"); queryTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, queryTimeout)
		defer cancel()
	}

	ch := make(chan dnsResult)
	go func(query *dns.Msg) {
		// dns.Clientはデフォルトで2秒しか待たないので、大きな値を設定してタイムアウトを実質無効にする
		// ExchangeContextWithConnを使いたかったが、dns.Connのconcurrency safetyが不明なので使わない
		result, rtt, err := (&dns.Client{Timeout: time.Duration(math.MaxInt64)}).ExchangeContext(
			ctx, query, fmt.Sprintf("%s:%d", viper.GetString("resolver.host"), viper.GetInt("resolver.port")))
		ch <- dnsResult{Result: result, RTT: rtt, Err: err}
	}(query.Copy()) // queryは以下でもアクセスするので、raceを避けるためにコピーしてgoroutineの引数に渡している

	logger = logger.With(
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

func base52Decode(encoded string) int32 {
	const space = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	const base = len(space)

	var decoded int32
	for i := 0; i < len(encoded); i++ {
		idx := strings.IndexByte(space, encoded[i])
		decoded = decoded*int32(base) + int32(idx)
	}
	return decoded
}

type myUint16 uint16

func (m myUint16) LogValue() slog.Value {
	return slog.StringValue(fmt.Sprintf("%x", m))
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
