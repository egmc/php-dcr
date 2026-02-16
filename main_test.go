package main

import (
	"regexp"
	"testing"
)

func TestParseRewriteRules(t *testing.T) {
	tests := []struct {
		name        string
		rawRules    []string
		wantCount   int
		wantErr     bool
		wantPattern string // first rule's regex pattern (if any)
		wantRepl    string // first rule's replacement (if any)
	}{
		{
			name:        "single rule",
			rawRules:    []string{"^/var/www/html::/home/user"},
			wantCount:   1,
			wantPattern: "^/var/www/html",
			wantRepl:    "/home/user",
		},
		{
			name:      "multiple rules",
			rawRules:  []string{"^/var/www/html::/home/user", `\.php\.cached$::.php`},
			wantCount: 2,
		},
		{
			name:        "capture groups",
			rawRules:    []string{`^/srv/([^/]+)/(.+)$::/data/$1/$2`},
			wantCount:   1,
			wantPattern: `^/srv/([^/]+)/(.+)$`,
			wantRepl:    "/data/$1/$2",
		},
		{
			name:        "named capture groups",
			rawRules:    []string{`^/var/www/(?P<site>[^/]+)/public/(?P<file>.+)$::/opt/sites/${site}/${file}`},
			wantCount:   1,
			wantPattern: `^/var/www/(?P<site>[^/]+)/public/(?P<file>.+)$`,
			wantRepl:    "/opt/sites/${site}/${file}",
		},
		{
			name:    "missing delimiter",
			rawRules: []string{"no-delimiter"},
			wantErr: true,
		},
		{
			name:    "invalid regex",
			rawRules: []string{"[invalid::/repl"},
			wantErr: true,
		},
		{
			name:      "empty slice",
			rawRules:  []string{},
			wantCount: 0,
		},
		{
			name:        "replacement contains double colon",
			rawRules:    []string{"^/a::/b::c"},
			wantCount:   1,
			wantPattern: "^/a",
			wantRepl:    "/b::c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := parseRewriteRules(tt.rawRules)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rules) != tt.wantCount {
				t.Fatalf("got %d rules, want %d", len(rules), tt.wantCount)
			}
			if tt.wantPattern != "" && rules[0].Regex.String() != tt.wantPattern {
				t.Errorf("pattern = %q, want %q", rules[0].Regex.String(), tt.wantPattern)
			}
			if tt.wantRepl != "" && rules[0].Replacement != tt.wantRepl {
				t.Errorf("replacement = %q, want %q", rules[0].Replacement, tt.wantRepl)
			}
		})
	}
}

func TestApplyRewriteRules(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		rules    []RewriteRule
		want     string
	}{
		{
			name:     "simple prefix replacement",
			filename: "/var/www/html/index.php",
			rules: []RewriteRule{
				{Regex: regexp.MustCompile(`^/var/www/html`), Replacement: "/home/user"},
			},
			want: "/home/user/index.php",
		},
		{
			name:     "no match",
			filename: "/other/path.php",
			rules: []RewriteRule{
				{Regex: regexp.MustCompile(`^/var/www/html`), Replacement: "/home/user"},
			},
			want: "/other/path.php",
		},
		{
			name:     "multiple rules applied sequentially",
			filename: "/var/www/html/index.php.cached",
			rules: []RewriteRule{
				{Regex: regexp.MustCompile(`^/var/www/html`), Replacement: "/home/user/project"},
				{Regex: regexp.MustCompile(`\.php\.cached$`), Replacement: ".php"},
			},
			want: "/home/user/project/index.php",
		},
		{
			name:     "positional capture groups",
			filename: "/srv/tenant-abc/v2/index.php",
			rules: []RewriteRule{
				{Regex: regexp.MustCompile(`^/srv/tenant-([^/]+)/([^/]+)/(.+)$`), Replacement: "/data/$2/$1/$3"},
			},
			want: "/data/v2/abc/index.php",
		},
		{
			name:     "named capture groups",
			filename: "/var/www/site1/public/page.php",
			rules: []RewriteRule{
				{Regex: regexp.MustCompile(`^/var/www/(?P<site>[^/]+)/public/(?P<file>.+)$`), Replacement: "/opt/sites/${site}/${file}"},
			},
			want: "/opt/sites/site1/page.php",
		},
		{
			name:     "empty rules",
			filename: "/any/path.php",
			rules:    []RewriteRule{},
			want:     "/any/path.php",
		},
		{
			name:     "nil rules",
			filename: "/any/path.php",
			rules:    nil,
			want:     "/any/path.php",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyRewriteRules(tt.filename, tt.rules)
			if got != tt.want {
				t.Errorf("applyRewriteRules(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestCstring(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "null terminated",
			input: []byte{'h', 'e', 'l', 'l', 'o', 0, 0, 0},
			want:  "hello",
		},
		{
			name:  "no null terminator",
			input: []byte{'a', 'b', 'c'},
			want:  "abc",
		},
		{
			name:  "null at start",
			input: []byte{0, 'a', 'b'},
			want:  "",
		},
		{
			name:  "empty slice",
			input: []byte{},
			want:  "",
		},
		{
			name: "512 byte buffer with null",
			input: func() []byte {
				b := make([]byte, MapKeyStrLen)
				copy(b, "/var/www/html/index.php")
				return b
			}(),
			want: "/var/www/html/index.php",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cstring(tt.input)
			if got != tt.want {
				t.Errorf("cstring(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
