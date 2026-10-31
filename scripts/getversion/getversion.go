// Command getversion prints Quisora's version (internal/build.Version), for the Taskfile's release and tag tasks.
package main

import (
	"fmt"

	"github.com/paularlott/quisora/internal/build"
)

func main() {
	fmt.Println(build.Version)
}
