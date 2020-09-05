package logfmt

import (
	"fmt"
	"time"
)

type Options struct {
	Timestamp bool
	Subject   bool
	Reply     bool
}

type Data struct {
	Timestamp time.Time
	Subject   string
	Reply     string
	Payload   string
}

func Format(d Data, opt Options) string {
	var ts, subject, reply string

	if opt.Timestamp {
		ts = fmt.Sprintf("%s", d.Timestamp.Format(time.RFC3339Nano))
	}

	if opt.Subject {
		subject = d.Subject
		if opt.Timestamp {
			subject = " " + subject
		}
	}

	if opt.Reply {
		reply = fmt.Sprintf("<%s>", d.Reply)
		if opt.Timestamp && !opt.Subject {
			reply = " " + reply
		}
	}

	if ts == "" && subject == "" && reply == "" {
		return d.Payload
	}

	return fmt.Sprintf("%s%s%s: %s", ts, subject, reply, d.Payload)
}
