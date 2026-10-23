package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"

	"github.com/paularlott/cli"
	cli_toml "github.com/paularlott/cli/toml"
)

// EnvPrefix starts every environment variable: QUISORA_ + the flag name in upper case with - as _.
const EnvPrefix = "QUISORA_"

// Setting is one configurable value: its flag, environment variable, config-file path and the field it fills.
type Setting struct {
	Flag  string // e.g. "postgres-dsn"
	Env   string // e.g. "QUISORA_POSTGRES_DSN"
	Path  string // TOML path, e.g. "storage.postgres.dsn"
	Usage string
	// Secret marks a value that must not be seen by others on the machine: given as a flag it is in the process list
	// (ps) and often in orchestration logs, so the config file or the environment are the places for it.
	Secret bool
	// Command names the one command that reads the setting (`cmd` tag; "" for every command that runs against the
	// configured server): its flag is offered there alone.
	Command string
	field   reflect.Value
}

// settings walks c and returns every setting, bound to c's fields. Struct fields with a `flag` tag prefix the flag
// names of the fields inside them.
func settings(c *Config) []Setting {
	var out []Setting
	var walk func(v reflect.Value, flagPrefix, pathPrefix string)
	walk = func(v reflect.Value, flagPrefix, pathPrefix string) {
		t := v.Type()
		for i := range t.NumField() {
			f, fv := t.Field(i), v.Field(i)
			path := pathPrefix + f.Tag.Get("toml")
			name := f.Tag.Get("flag")
			if f.Type.Kind() == reflect.Struct {
				p := flagPrefix
				if name != "" {
					p += name + "-"
				}
				walk(fv, p, path+".")
				continue
			}
			if name == "" {
				continue
			}
			flag := flagPrefix + name
			out = append(out, Setting{Flag: flag, Env: EnvPrefix + strings.ToUpper(strings.ReplaceAll(flag, "-", "_")),
				Path: path, Usage: f.Tag.Get("usage"), Secret: f.Tag.Get("secret") == "true", Command: f.Tag.Get("cmd"), field: fv})
		}
	}
	walk(reflect.ValueOf(c).Elem(), "", "")
	return out
}

// Value is the setting's current value as text (a list's values joined by commas).
func (s Setting) Value() string {
	switch s.field.Kind() {
	case reflect.String:
		return s.field.String()
	case reflect.Slice:
		var out []string
		for i := range s.field.Len() {
			out = append(out, fmt.Sprint(s.field.Index(i).Interface()))
		}
		return strings.Join(out, ",")
	}
	return fmt.Sprint(s.field.Interface())
}

// Settings lists every setting of c (for documentation and tests).
func Settings(c *Config) []Setting { return settings(c) }

// FlagSet is the command-line flags of every setting, bound to a configuration.
type FlagSet struct {
	// Global are the log settings, for the root command, so every command honours them.
	Global []cli.Flag
	// Server are the rest, for the commands that run against the configured server (serve, invite, the load test
	// tool's seed, ...).
	Server []cli.Flag
	// Command are the flags of settings only one command reads (`cmd` tag), by command name, to add to Server there.
	Command map[string][]cli.Flag
}

// For returns the flags of the named command: Server plus its own.
func (fs FlagSet) For(command string) []cli.Flag {
	return append(slices.Clone(fs.Server), fs.Command[command]...)
}

// Flags returns a command-line flag for every setting, bound to c (which should hold the defaults). The cli package
// fills each from, in order: the flag, its QUISORA_* environment variable, its key in the config file, the default.
func Flags(c *Config) FlagSet {
	fs := FlagSet{Command: map[string][]cli.Flag{}}
	for _, s := range settings(c) {
		var f cli.Flag
		global := strings.HasPrefix(s.Flag, "log-")
		paths, envs := []string{s.Path}, []string{s.Env}
		switch p := s.field.Addr().Interface().(type) {
		case *string:
			f = &cli.StringFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
				DefaultValue: *p, AssignTo: p, Global: global}
		case *int:
			f = &cli.IntFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
				DefaultValue: *p, AssignTo: p, Global: global}
		case *bool:
			f = &cli.BoolFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
				DefaultValue: *p, AssignTo: p, Global: global}
		case *[]string:
			f = &cli.StringSliceFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
				DefaultValue: *p, AssignTo: p, Global: global}
		default:
			continue
		}
		switch {
		case global:
			fs.Global = append(fs.Global, f)
		case s.Command != "":
			fs.Command[s.Command] = append(fs.Command[s.Command], f)
		default:
			fs.Server = append(fs.Server, f)
		}
	}
	return fs
}

// FileName is the configuration file looked for in the search path when --config is not given.
const FileName = "quisora.toml"

// NewConfigFile returns the TOML configuration file source for a command tree's root and its --config flag (also
// QUISORA_CONFIG), and records the source in c (Validate checks its keys). Without --config, quisora.toml is looked
// for in the current directory, ~/.config/quisora and /etc/quisora.
func NewConfigFile(c *Config) (cli.ConfigFileSource, cli.Flag) {
	name := FileName
	src := cli_toml.NewConfigFile(&name, func() []string {
		paths := []string{"."}
		if home, err := os.UserHomeDir(); err == nil {
			paths = append(paths, filepath.Join(home, ".config", "quisora"))
		}
		if runtime.GOOS != "windows" {
			paths = append(paths, "/etc/quisora")
		}
		return paths
	})
	c.ConfigFile = src
	return src, &cli.StringFlag{Name: "config", Aliases: []string{"c"}, AssignTo: &name, Global: true,
		Usage:       "Configuration file (TOML)",
		DefaultText: FileName + " in the current directory, ~/.config/quisora/ or /etc/quisora/",
		EnvVars:     []string{EnvPrefix + "CONFIG"}}
}
