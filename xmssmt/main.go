package main

import (
	"fmt"
	"os"

	"github.com/bwesterb/go-xmssmt"

	"github.com/urfave/cli"
)

func cmdAlgs(c *cli.Context) error {
	for _, name := range xmssmt.ListNames() {
		ctx := xmssmt.NewContextFromName(name)
		fmt.Printf("%s\n", ctx.Name())
	}

	return nil
}

func main() {
	app := cli.NewApp()

	app.Commands = []cli.Command{
		{
			Name:   "algs",
			Usage:  "List XMSS[MT] instances",
			Action: cmdAlgs,
		},
	}

	app.Run(os.Args)
}
