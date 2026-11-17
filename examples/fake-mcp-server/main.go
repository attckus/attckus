// Command fake-mcp-server is an order-management MCP server for demos and
// end-to-end tests: read, write, destroy and external tools.
//
//	fake-mcp-server                 stdio
//	fake-mcp-server --http :9000    Streamable HTTP (JSON responses)
//	--poison    add a tool with injected instructions in its description
//	--rug-pull  change send_email's description after the first listing
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/attckus/attckus/internal/mcptest"
)

func main() {
	addr := flag.String("http", "", "serve Streamable HTTP on this address instead of stdio")
	poison := flag.Bool("poison", false, "serve a poisoned tool")
	rug := flag.Bool("rug-pull", false, "change a tool definition after the first tools/list")
	flag.Parse()
	srv := &mcptest.Server{Poison: *poison, RugPull: *rug}
	if *addr != "" {
		log.Printf("fake MCP server on http://%s", *addr)
		hs := &http.Server{Addr: *addr, Handler: srv, ReadHeaderTimeout: 5 * time.Second}
		log.Fatal(hs.ListenAndServe())
	}
	if err := srv.ServeStdio(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
