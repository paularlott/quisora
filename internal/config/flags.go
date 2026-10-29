package config

import (
	"cmp"
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
	// Commands are the commands that offer the setting's flag (`cmd` tag): serve alone when there is none, "*" for
	// every command.
	Commands []string
	field    reflect.Value
}

// offeredBy reports whether command offers the setting's flag.
func (s Setting) offeredBy(command string) bool { return slices.Contains(s.Commands, command) }

// global reports whether every command offers the setting's flag (a global flag of the root command).
func (s Setting) global() bool { return s.offeredBy("*") }

// settings walks c and returns every setting, bound to c's fields. Struct fields with a `flag` tag prefix the flag
// names of the fields inside them, and their `cmd` tag is that of the fields inside them that have none.
func settings(c *Config) []Setting {
	var out []Setting
	var walk func(v reflect.Value, flagPrefix, pathPrefix, cmds string)
	walk = func(v reflect.Value, flagPrefix, pathPrefix, cmds string) {
		t := v.Type()
		for i := range t.NumField() {
			f, fv := t.Field(i), v.Field(i)
			path := pathPrefix + f.Tag.Get("toml")
			name := f.Tag.Get("flag")
			cmds := cmp.Or(f.Tag.Get("cmd"), cmds)
			if f.Type.Kind() == reflect.Struct {
				p := flagPrefix
				if name != "" {
					p += name + "-"
				}
				walk(fv, p, path+".", cmds)
				continue
			}
			if name == "" {
				continue
			}
			flag := flagPrefix + name
			out = append(out, Setting{Flag: flag, Env: EnvPrefix + strings.ToUpper(strings.ReplaceAll(flag, "-", "_")),
				Path: path, Usage: f.Tag.Get("usage"), Secret: f.Tag.Get("secret") == "true", Commands: strings.Fields(cmds),
				field: fv})
		}
	}
	walk(reflect.ValueOf(c).Elem(), "", "", "serve")
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
	// Global are the flags every command offers (`cmd:"*"`: the log level and format), for the root command.
	Global   []cli.Flag
	settings []Setting
}

// For returns the flags of the named command. Those of the settings it offers (`cmd` tag) are its own; every other
// setting is bound too, hidden, so that the config file and the environment, which every command shares with serve,
// are read whole and validated as one. Given on the command line, those are refused (Refuse).
func (fs FlagSet) For(command string) []cli.Flag {
	var out []cli.Flag
	for _, s := range fs.settings {
		if !s.global() {
			out = append(out, s.flag(!s.offeredBy(command)))
		}
	}
	return out
}

// Refuse refuses a setting given on the command line of c that c does not offer as a flag (For).
func (fs FlagSet) Refuse(c *cli.Command) error {
	for _, s := range fs.settings {
		if !s.global() && !s.offeredBy(c.Name) && c.FlagSource(s.Flag) == cli.SourceCommandLine {
			return fmt.Errorf("--%s is not a flag of %s: the command does not use %s", s.Flag, c.Name, s.Path)
		}
	}
	return nil
}

// Flags returns the command-line flags of every setting, bound to c (which should hold the defaults). The cli package
// fills each from, in order: the flag, its QUISORA_* environment variable, its key in the config file, the default.
func Flags(c *Config) FlagSet {
	fs := FlagSet{settings: settings(c)}
	for _, s := range fs.settings {
		if s.global() {
			fs.Global = append(fs.Global, s.flag(false))
		}
	}
	return fs
}

// flag is the setting's command-line flag.
func (s Setting) flag(hidden bool) cli.Flag {
	paths, envs, global := []string{s.Path}, []string{s.Env}, s.global()
	switch p := s.field.Addr().Interface().(type) {
	case *string:
		return &cli.StringFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
			DefaultValue: *p, AssignTo: p, Global: global, Hidden: hidden}
	case *int:
		return &cli.IntFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
			DefaultValue: *p, AssignTo: p, Global: global, Hidden: hidden}
	case *bool:
		return &cli.BoolFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
			DefaultValue: *p, AssignTo: p, Global: global, Hidden: hidden}
	case *[]string:
		return &cli.StringSliceFlag{Name: s.Flag, Usage: s.Usage, ConfigPath: paths, EnvVars: envs,
			DefaultValue: *p, AssignTo: p, Global: global, Hidden: hidden}
	}
	panic("config: no flag type for setting " + s.Path)
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
