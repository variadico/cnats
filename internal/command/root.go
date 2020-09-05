package command

import (
	"github.com/spf13/cobra"
	"github.com/variadico/natstk/internal/command/pubcmd"
	"github.com/variadico/natstk/internal/command/subcmd"
	"github.com/variadico/natstk/internal/command/statscmd"
	"github.com/variadico/natstk/internal/command/credscmd"
)

func Root() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "natstk [command]",
		Short: "NATS Tool Kit",
	}

	cmd.AddCommand(pubcmd.Cmd())
	cmd.AddCommand(subcmd.Cmd())
	cmd.AddCommand(statscmd.Cmd())
	cmd.AddCommand(credscmd.Cmd())

	return cmd
}
