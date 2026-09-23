package buildinfo2

import "strings"

var Version = "dev"

func UserAgent() string { return strings.ToLower("shop/" + Version) }
