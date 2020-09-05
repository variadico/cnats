package subcmd

import (
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
	response     []byte
	queue        string
	outputFields logfmt.Options
	count        int
	credsFile    string
	waitIncoming bool

	subject string
}

func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "sub [options] <subject>",
		Short:         "Subscribe to messages on a subject",
		RunE:          runE,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().StringP("credentials-file", "a", "", "user credentials file")
	cmd.Flags().StringP("urls", "u", "nats://127.0.0.1:4222", "comma separated list of NATS server URLs, e.g. nats://demo.nats.io")
	cmd.Flags().StringP("response", "r", "", "payload to response to request")
	cmd.Flags().StringP("queue", "q", "", "queue group name")
	cmd.Flags().StringP("output-fields", "f", "", "comma separated list of fields to include in output")
	cmd.Flags().IntP("count", "c", 0, "max messages to receive")
	cmd.Flags().BoolP("wait", "w", false, "wait forever for incoming requests")

	return cmd
}

func runE(cmd *cobra.Command, args []string) error {
	opt, err := getOptions(cmd.Flags(), args)
	if err != nil {
		return fmt.Errorf("failed to read options: %w", err)
	}

	nc, err := nats.Connect(opt.urls, getNATSOptions(opt)...)
	if err != nil {
		return err
	}
	defer nc.Close()

	var sub *nats.Subscription
	if opt.queue != "" {
		sub, err = nc.QueueSubscribeSync(args[0], opt.queue)
	} else {
		sub, err = nc.SubscribeSync(args[0])
	}
	if err != nil {
		return err
	}

	if opt.count > 0 {
		if err := sub.AutoUnsubscribe(opt.count); err != nil {
			return err
		}
	}

	errc := make(chan error)
	go handleInterrupt(sub, errc)
	go handleMessages(sub, opt, errc)

	return <-errc
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
		return options{}, fmt.Errorf("missing subscribe subject")
	}
	opt.subject = args[0]

	s, err := flags.GetString("response")
	if err != nil {
		return options{}, err
	}
	if s != "" {
		opt.response = []byte(s)
	}
	if s == "-" {
		bs, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return options{}, err
		}
		opt.response = bs
	}

	opt.queue, err = flags.GetString("queue")
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

	opt.count, err = flags.GetInt("count")
	if err != nil {
		return options{}, err
	}

	opt.credsFile, err = flags.GetString("credentials-file")
	if err != nil {
		return options{}, err
	}

	opt.waitIncoming, err = flags.GetBool("wait")
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

func handleMessages(sub *nats.Subscription, opt options, errc chan<- error) {
	for {
		m, err := sub.NextMsg(3 * time.Second)
		if err == nats.ErrBadSubscription {
			// Probably because subscription is being drained.
			errc <- nil
			return
		} else if err == nats.ErrMaxMessages {
			// Received max number of messages.
			errc <- nil
			return
		} else if err == nats.ErrTimeout {
			// Normal, keep waiting. Maybe more messages will arrive.
			continue
		} else if err != nil {
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

		if opt.response != nil && m.Reply != "" {
			err := m.Respond(opt.response)
			if !opt.waitIncoming {
				errc <- err
				return
			}

			if err != nil {
				errc <- err
			}
		}
	}
}

func handleInterrupt(sub *nats.Subscription, errc chan<- error) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	<-c
	if err := sub.Unsubscribe(); err != nil {
		errc <- fmt.Errorf("failed to unsubscribe: %v", err)
		return
	}
	if err := sub.Drain(); err != nil {
		errc <- fmt.Errorf("failed to drain pending messages: %v", err)
	}
}
