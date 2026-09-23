package buildinfo

import "strings"

var _ = strings.ToUpper

// Version is set via -ldflags "-X".
var Version = "dev"

func UserAgent() string { return "shop/" + Version }
