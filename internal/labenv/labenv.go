// Package labenv reads lab/lab.env, the lab's KEY=value constants, into a struct by its env tags.
package labenv

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/caarlos0/env/v11"
)

// Load fills v from file by v's env tags (github.com/caarlos0/env); every tagged key without a default is required.
func Load(file string, v any) error {
	m, err := read(file)
	if err != nil {
		return err
	}
	if err := env.ParseWithOptions(v, env.Options{Environment: m, RequiredIfNoDef: true}); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	return nil
}

// read parses KEY=value lines, skipping blank lines and comments.
func read(file string) (map[string]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s: %q", file, line)
		}
		m[k] = v
	}
	return m, s.Err()
}
