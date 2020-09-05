package statscmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type options struct {
	url   string
	path  string
	query string
}

func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "stats <type> [key=val key=val ...]",
		Short:         "Query the HTTP monitoring port",
		RunE:          runE,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().StringP("url", "u", "http://127.0.0.1:8222", "NATS server monitoring URL")

	return cmd
}

func runE(cmd *cobra.Command, args []string) error {
	opt, err := getOptions(cmd.Flags(), args)
	if err != nil {
		return fmt.Errorf("failed to read options: %w", err)
	}

	hc := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := hc.Get(fmt.Sprintf("%s/%s%s", opt.url, opt.path, opt.query))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(os.Stdout, resp.Body)
	fmt.Println()
	return err
}

func getOptions(flags *pflag.FlagSet, args []string) (options, error) {
	var opt options
	var err error

	opt.url, err = flags.GetString("url")
	if err != nil {
		return options{}, err
	}
	if opt.url == "" {
		return options{}, fmt.Errorf("missing NATS monitoring URL")
	}
	opt.url = strings.TrimSuffix(opt.url, "/")

	if len(args) == 0 {
		return options{}, fmt.Errorf("missing monitoring type and args")
	}
	opt.path = args[0]

	vals := make(url.Values)
	for _, kv := range args[1:] {
		sps := strings.Split(kv, "=")
		if len(sps) != 2 {
			return options{}, fmt.Errorf("bad key-value: %s", kv)
		}

		vals.Set(sps[0], sps[1])
	}
	if len(vals) > 0 {
		opt.query = "?" + vals.Encode()
	}

	return opt, nil
}
