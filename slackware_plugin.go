// MIT License

// Copyright (c) 2020,2022-2024 Andrew Clemons

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

func main() {
	socketPtr := flag.String("socket", "socket-path", "socket path")
	flag.String("timeout", "12", "timeout")
	flag.String("interval", "3", "interval")
	flag.Parse()

	server, err := osquery.NewExtensionManagerServer("slackware_packages", *socketPtr)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin("slackware_packages", SlackwarePackagesColumns(), SlackwarePackagesGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

func SlackwarePackagesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("version"),
		table.TextColumn("arch"),
		table.TextColumn("build"),
		table.TextColumn("tag"),
	}
}

func SlackwarePackagesGenerate(_ context.Context, _ table.QueryContext) ([]map[string]string, error) {
	// slackware 15.0 package directory
	packageDir := "/var/lib/pkgtools/packages/"

	_, err := os.Stat(packageDir)

	if os.IsNotExist(err) {
		// slackware 14.2 and older package directory
		packageDir = "/var/log/packages"
	}

	files, err := os.ReadDir(packageDir)
	if err != nil {
		return nil, err
	}

	var results []map[string]string

	for _, file := range files {
		parts := strings.Split(file.Name(), "-")
		version := parts[len(parts)-3]
		arch := parts[len(parts)-2]
		build := parts[len(parts)-1]
		tag := ""
		if strings.Index(build, "_") > 0 {
			buildParts := strings.Split(build, "_")
			build = buildParts[0]
			tag = buildParts[len(buildParts)-1]
		}

		parts = parts[:len(parts)-3]

		name := strings.Join(parts, "-")

		hash := map[string]string{
			"name":    name,
			"version": version,
			"arch":    arch,
			"build":   build,
			"tag":     tag,
		}

		results = append(results, hash)
	}

	return results, nil
}
