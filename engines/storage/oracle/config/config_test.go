package config

import (
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	valid := Config{ConnectString: "db:1521/service", Username: "LAMASSU", MaxOpenConns: 20, MaxIdleConns: 5, ConnMaxLifetime: 30 * time.Minute}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"missing connect string", func(c *Config) { c.ConnectString = " " }},
		{"missing username", func(c *Config) { c.Username = "" }},
		{"negative open", func(c *Config) { c.MaxOpenConns = -1 }},
		{"negative idle", func(c *Config) { c.MaxIdleConns = -1 }},
		{"negative lifetime", func(c *Config) { c.ConnMaxLifetime = -1 }},
		{"idle exceeds open", func(c *Config) { c.MaxIdleConns = 21 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.edit(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDecodeDuration(t *testing.T) {
	c, err := Decode(map[string]any{
		"connect_string": "tcps://db:1521/service", "username": "LAMASSU",
		"password": "secret", "conn_max_lifetime": "30m",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.ConnMaxLifetime != 30*time.Minute || string(c.Password) != "secret" {
		t.Fatalf("incorrect decoded configuration: lifetime %v", c.ConnMaxLifetime)
	}
	if _, err := Decode(map[string]any{"connect_string": "db", "username": "user", "conn_max_lifetime": "wrong"}); err == nil {
		t.Fatal("expected invalid duration error")
	}
}
