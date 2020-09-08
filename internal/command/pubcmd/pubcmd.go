package pubcmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/variadico/natstk/internal/logfmt"
)

type options struct {
	urls         string
	request      bool
	outputFields logfmt.Options
	hz           int64
	count        int
	credsFile    string

	subject string
	payload []byte
}

func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "pub [options] <subject> [payload]",
		Short:         "Publish messages on a subject",
		RunE:          runE,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().StringP("credentials-file", "a", "", "user credentials file")
	cmd.Flags().StringP("urls", "u", "nats://127.0.0.1:4222", "comma separated list of NATS server URLs, e.g. nats://demo.nats.io")
	cmd.Flags().BoolP("request", "r", false, "publish a request on a topic")
	cmd.Flags().StringP("output-fields", "f", "", "comma separated list of fields to include in output")
	cmd.Flags().Int64P("hz", "z", 0, "publishing rate")
	cmd.Flags().IntP("count", "c", 0, "max messages to send")

	return cmd
}

func runE(cmd *cobra.Command, args []string) error {
	opt, err := getOptions(cmd.Flags(), args)
	if err != nil {
		return err
	}

	nc, err := nats.Connect(opt.urls, getNATSOptions(opt)...)
	if err != nil {
		return err
	}
	defer nc.Close()

	errc := make(chan error)

	go handleInterrupt(nc, errc)
	go handleMessages(nc, opt, errc)

	err = <-errc
	if err != nil {
		return err
	}

	// Check if there are any publish permission violations.
	if err := nc.FlushTimeout(1 * time.Second); err != nil {
		return err
	}
	return nc.LastError()
}

func getOptions(flags *pflag.FlagSet, args []string) (opt options, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to get options: %w", err)
		}
	}()

	opt.urls, err = flags.GetString("urls")
	if err != nil {
		return options{}, err
	}
	if opt.urls == "" {
		return options{}, fmt.Errorf("missing NATS server URLs")
	}

	if len(args) == 0 {
		return options{}, fmt.Errorf("missing publish subject")
	} else if len(args) == 1 {
		args = append(args, "")
	}
	opt.subject = args[0]
	opt.payload = []byte(args[1])

	opt.request, err = flags.GetBool("request")
	if err != nil {
		return options{}, err
	}

	outputFields, err := flags.GetString("output-fields")
	if err != nil {
		return options{}, err
	}
	if !flags.Changed("output-fields") {
		opt.outputFields.Timestamp = true
		opt.outputFields.Subject = true
		opt.outputFields.Reply = true
	} else {
		for _, f := range strings.Split(outputFields, ",") {
			switch strings.TrimSpace(f) {
			case "time":
				opt.outputFields.Timestamp = true
			case "subject":
				opt.outputFields.Subject = true
			case "reply":
				opt.outputFields.Reply = true
			}
		}
	}

	opt.hz, err = flags.GetInt64("hz")
	if err != nil {
		return options{}, err
	}

	opt.count, err = flags.GetInt("count")
	if err != nil {
		return options{}, err
	}

	opt.credsFile, err = flags.GetString("credentials-file")
	if err != nil {
		return options{}, err
	}

	return opt, nil
}

func getNATSOptions(opt options) []nats.Option {
	var natsOpt []nats.Option

	natsOpt = append(natsOpt, nats.Name("natstk"))

	if opt.credsFile != "" {
		natsOpt = append(natsOpt, nats.UserCredentials(opt.credsFile))
	}

	natsOpt = append(natsOpt, func(o *nats.Options) error {
		o.Pedantic = true
		return nil
	})

	natsOpt = append(natsOpt, nats.DrainTimeout(3*time.Second))

	return natsOpt
}

func handleMessages(nc *nats.Conn, opt options, errc chan<- error) {
	second := (1 * time.Second).Nanoseconds()

	if bytes.Compare(opt.payload, []byte("-")) == 0 {
		bs, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			errc <- err
			return
		}
		opt.payload = bs
	}

	if !opt.request {
		if opt.hz > 0 {
			sleepDur := time.Duration(second / opt.hz)

			if opt.count > 0 {
				for i := 0; i < opt.count; i++ {
					err := nc.Publish(opt.subject, opt.payload)
					if err == nats.ErrConnectionClosed || err == nats.ErrConnectionDraining {
						errc <- nil
						return
					} else if err != nil {
						errc <- err
						return
					}
					time.Sleep(sleepDur)
				}
				errc <- nil
				return
			}

			for {
				err := nc.Publish(opt.subject, opt.payload)
				if err == nats.ErrConnectionClosed || err == nats.ErrConnectionDraining {
					errc <- nil
					return
				} else if err != nil {
					errc <- err
					return
				}
				time.Sleep(sleepDur)
			}
		} // end hz

		errc <- nc.Publish(opt.subject, opt.payload)
		return
	}

	m, err := nc.Request(opt.subject, opt.payload, 5*time.Second)
	if err != nil {
		errc <- err
		return
	}

	d := logfmt.Data{
		Payload:   string(m.Data),
		Subject:   m.Subject,
		Reply:     m.Reply,
		Timestamp: time.Now(),
	}
	fmt.Println(logfmt.Format(d, opt.outputFields))
	errc <- nil
}

func handleInterrupt(nc *nats.Conn, errc chan<- error) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	if err := nc.Drain(); err != nil {
		errc <- fmt.Errorf("failed to drain pending messages: %v", err)
	}
}
