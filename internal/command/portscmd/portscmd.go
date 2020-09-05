package portscmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	minPort = 0
	maxPort = 65535
)

type options struct {
	domain  string
	workers int
	timeout time.Duration
}

type workResult struct {
	addr string
	kind string
	err  error
}

func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "ports <domain>",
		Short:         "Scan for NATS ports on domain",
		RunE:          runE,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().IntP("workers", "w", 1000, "number of workers to spawn")
	cmd.Flags().StringP("timeout", "t", "30s", "timeout duration")

	return cmd
}

func runE(cmd *cobra.Command, args []string) error {
	opt, err := getOptions(cmd.Flags(), args)
	if err != nil {
		return fmt.Errorf("failed to read options: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), opt.timeout)
	defer cancel()

	wrkc := workChan(ctx, opt.domain)
	resc := make(chan workResult)

	var wg sync.WaitGroup
	wg.Add(opt.workers)
	for i := 0; i < opt.workers; i++ {
		go func() {
			defer wg.Done()
			scanPort(ctx, wrkc, resc)
		}()
	}

	go func() {
		defer close(resc)
		wg.Wait()
	}()

	i := -1
	for res := range resc {
		i++
		if i%1000 == 0 {
			log.Printf("%.2f%%...\n", float64(float64(i)/float64(maxPort))*100.00)
		}

		if res.err != nil {
			return res.err
		} else if res.kind == "CLOSED" {
			continue
		}

		fmt.Println(res.addr, res.kind)
	}

	return nil
}

func getOptions(flags *pflag.FlagSet, args []string) (options, error) {
	var opt options
	var err error

	if len(args) == 0 {
		return options{}, fmt.Errorf("missing domain")
	}
	opt.domain = args[0]

	opt.workers, err = flags.GetInt("workers")
	if err != nil {
		return options{}, err
	}

	tout, err := flags.GetString("timeout")
	if err != nil {
		return options{}, err
	}
	opt.timeout, err = time.ParseDuration(tout)
	if err != nil {
		return options{}, err
	}

	return opt, nil
}

func workChan(ctx context.Context, domain string) <-chan string {
	ch := make(chan string)

	go func() {
		defer close(ch)
		for port := minPort; port <= maxPort; port++ {
			select {
			case ch <- fmt.Sprintf("%s:%d", domain, port):
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch
}

func scanPort(ctx context.Context, wrkc <-chan string, resc chan<- workResult) {
	for addr := range wrkc {
		func() {
			d := net.Dialer{Timeout: 8 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				if txt := err.Error(); strings.Contains(txt, "busy") {
					resc <- workResult{err: fmt.Errorf("failed to dial %s: %w", addr, err)}
					return
				}
				resc <- workResult{addr: addr, kind: "CLOSED"}
				return
			}
			defer conn.Close()

			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				resc <- workResult{err: fmt.Errorf("failed to set %s read deadline: %w", addr, err)}
				return
			}

			kind := "OPEN"

			buf := make([]byte, 4)
			n, err := conn.Read(buf)
			if err != nil {
				resc <- workResult{addr: addr, kind: kind}
				return
			}

			if prefix := string(buf[:n]); prefix == "INFO" {
				kind = "OPEN-NATS"
			}
			resc <- workResult{addr: addr, kind: kind}
		}()

		select {
		case <-ctx.Done():
			resc <- workResult{err: ctx.Err()}
			return
		default:
		}
	}
}
