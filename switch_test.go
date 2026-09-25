package main

import "testing"

func TestSwitchOriginHost(t *testing.T) {
	cases := []struct {
		origin  string
		from    string
		to      string
		want    string
		matched bool
	}{
		{"docker11.srv:5002", "docker11.srv", "docker12.srv", "docker12.srv:5002", true},
		{"docker11.srv", "docker11.srv", "docker12.srv", "docker12.srv", true},
		{"https://docker11.srv:9443/api", "docker11.srv", "docker12.srv", "https://docker12.srv:9443/api", true},
		{"http://docker11.srv:5003/health", "docker11.srv", "10.0.0.5", "http://10.0.0.5:5003/health", true},
		{"docker13.srv:5003", "docker11.srv", "docker12.srv", "", false},
		{"[fd::1]:2375", "fd::1", "docker12.srv", "docker12.srv:2375", true},
		{"diskstation.srv:5001", "docker11.srv", "docker12.srv", "", false},
		{"DOCKER11.SRV:8000", "docker11.srv", "docker12.srv", "docker12.srv:8000", true},
	}
	for _, c := range cases {
		got, matched := switchOriginHost(c.origin, c.from, c.to)
		if matched != c.matched || got != c.want {
			t.Errorf("switchOriginHost(%q,%q,%q) = %q,%v want %q,%v",
				c.origin, c.from, c.to, got, matched, c.want, c.matched)
		}
	}
}
