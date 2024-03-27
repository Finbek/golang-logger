package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"log/syslog"
	"os"
	"sync"

	"github.com/fatih/color"
)

const (
	LevelManual = slog.Level(16)
	LevelStatus = slog.Level(12)
)

const (
	timeFormat = "[15:05:05.000]"
)

// colors used by logger
var (
	tableHeaderColor = color.New(color.FgHiWhite)
	tableRowColor    = color.New(color.FgWhite)
	infoColor        = color.BlueString
	debugColor       = color.MagentaString
	warnColor        = color.YellowString
	errorColor       = color.RedString
	msgColor         = color.CyanString
	attrColor        = color.New(color.FgWhite)
	manualColor      = color.New(color.FgHiGreen, color.Bold, color.BgBlack)
	manualMessage    = color.HiGreenString
)

type PrettyHandlerOptions struct {
	SlogOpts slog.HandlerOptions
}

type PrettyHandler struct {
	slog.Handler
	l *log.Logger
	b *bytes.Buffer
	m *sync.Mutex
}

type Logger struct {
	logger *slog.Logger
}

// ------------------------------------------------------------
// ================= Logger Init ==============================
// ------------------------------------------------------------
var logLevel *slog.LevelVar = &slog.LevelVar{} //we can reset it later

var opts PrettyHandlerOptions = PrettyHandlerOptions{
	SlogOpts: slog.HandlerOptions{
		Level:       logLevel,
		ReplaceAttr: suppressDefaults(nil),
		AddSource:   false,
	},
}

var logger Logger = Logger{
	logger: slog.New(initHandler()),
}

func initHandler() *PrettyHandler {

	syslogger, err := syslog.New(syslog.LOG_INFO, "ANTPMDC")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	multi := io.MultiWriter(syslogger, os.Stdout)

	handler := NewPrettyHandler(multi, &opts)

	return handler
}

// ------------------------------------------------------------
// ================= New Custom Handler =======================
// ------------------------------------------------------------

func NewPrettyHandler(out io.Writer, opts *PrettyHandlerOptions) *PrettyHandler {

	b := &bytes.Buffer{}
	return &PrettyHandler{
		b:       b,
		Handler: slog.NewJSONHandler(b, &opts.SlogOpts),
		l:       log.New(out, "", 0),

		m: &sync.Mutex{},
	}
}

func (h *PrettyHandler) Handle(ctx context.Context, r slog.Record) (err error) {
	level := r.Level.String() + ":"
	switch r.Level {
	case slog.LevelDebug:
		level = debugColor(level)
	case slog.LevelInfo:
		level = infoColor(level)
	case slog.LevelWarn:
		level = warnColor(level)
	case slog.LevelError:
		level = errorColor(level)
	case LevelManual, LevelStatus:

		logMsg := msgColor(r.Message)
		attrs, err := h.computeAttrs(ctx, r)
		if err != nil {
			h.l.Println(err)
		}
		for _, v := range attrs {
			logMsg += " " + manualMessage(fmt.Sprintf("%v", v))
		}
		fmt.Println(logMsg)
		return err
	}

	timeStr := r.Time.Format(timeFormat)
	msg := msgColor(r.Message)
	logMsg := timeStr + " " + level + " " + msg

	attrs, err := h.computeAttrs(ctx, r)
	if err != nil {
		return err
	}
	if len(attrs) > 0 {
		bytes, err := json.MarshalIndent(attrs, "", "  ")
		if err != nil {
			return fmt.Errorf("error when marshaling attrs: %w", err)
		}
		logMsg += " " + attrColor.Sprint(string(bytes))
	}
	h.l.Print(logMsg)

	return nil
}

func (h *PrettyHandler) computeAttrs(ctx context.Context, r slog.Record) (map[string]any, error) {
	h.m.Lock()
	defer func() {
		h.b.Reset()
		h.m.Unlock()
	}()
	if err := h.Handler.Handle(ctx, r); err != nil {
		return nil, fmt.Errorf("error when calling inner handler's Handle: %w", err)
	}

	var attrs map[string]any
	err := json.Unmarshal(h.b.Bytes(), &attrs)
	if err != nil {
		return nil, fmt.Errorf("error when unmarshaling inner handler's Handle result: %w", err)
	}
	return attrs, nil
}

func suppressDefaults(next func([]string, slog.Attr) slog.Attr) func([]string, slog.Attr) slog.Attr {
	return func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey ||
			a.Key == slog.LevelKey ||
			a.Key == slog.MessageKey {
			return slog.Attr{}
		}
		if next == nil {
			return a
		}
		return next(groups, a)
	}
}

// ------------------------------------------------------------
// ================= Public Methods to use logger ==============
// ------------------------------------------------------------
func Info(msg string, args ...any) {
	logger.logger.Info(msg, args...)
}

func Debug(msg string, args ...any) {
	logger.logger.Debug(msg, args...)

}

// args better use slog attr like slog.Any("err", error) slog.String and etc, first value is key and second is value
func Error(msg string, args ...any) {
	logger.logger.ErrorContext(context.Background(), msg, args...)
}

func Warn(msg string, args ...any) {
	logger.logger.Warn(msg, args...)
}

func Manual(msg string, args ...any) {
	ctx := context.TODO()
	logger.logger.Log(ctx, LevelManual, msg, args...)
}

func Status(msg string, args ...any) {
	ctx := context.TODO()
	logger.logger.Log(ctx, LevelManual, msg, args...)
}
func SetDefault() {
	slog.SetDefault(logger.logger)
}

func SetLogLevel(level slog.Level) {
	logLevel.Set(level)
}

