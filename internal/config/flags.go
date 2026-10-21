package config

import (
	"reflect"
	"strings"

	"github.com/paularlott/cli"
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
	field  reflect.Value
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
				Path: path, Usage: f.Tag.Get("usage"), Secret: f.Tag.Get("secret") == "true", field: fv})
		}
	}
	walk(reflect.ValueOf(c).Elem(), "", "")
	return out
}

// Settings lists every setting of c (for documentation and tests).
func Settings(c *Config) []Setting { return settings(c) }

// Flags returns a command-line flag for every setting, bound to c (which should hold the defaults). The cli package
// fills each from, in order: the flag, its QUISORA_* environment variable, its key in the config file, the default.
// The log settings come back separately as global flags (for the root command, so every command honours them);
// the rest are for the commands that run against the configured server (serve, invite, and the load test tool's seed).
func Flags(c *Config) (globalFlags, server []cli.Flag) {
	for _, s := range settings(c) {
		out := &server
		global := strings.HasPrefix(s.Flag, "log-")
		if global {
			out = &globalFlags
		}
		paths, envs := []string{s.Path}, []string{s.Env}
		switch p := s.field.Addr().Interface().(type) {
		case *string:
			*out = append(*out, &cli.StringFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
				DefaultValue: *p, AssignTo: p, Global: global})
		case *int:
			*out = append(*out, &cli.IntFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
				DefaultValue: *p, AssignTo: p, Global: global})
		case *bool:
			*out = append(*out, &cli.BoolFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
				DefaultValue: *p, AssignTo: p, Global: global})
		case *[]string:
			*out = append(*out, &cli.StringSliceFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
				DefaultValue: *p, AssignTo: p, Global: global})
		}
	}
	return globalFlags, server
}
