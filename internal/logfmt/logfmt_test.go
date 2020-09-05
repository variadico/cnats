package logfmt

import (
	"testing"
)

func TestMsgFormat(t *testing.T) {
	d := Data{
		Payload: "hello",
		Subject: "foo",
		Reply:   "bar",
	}

	cases := []struct {
		opt  Options
		want string
	}{
		{
			opt: Options{
				Timestamp: true,
				Subject:   true,
				Reply:     true,
			},
			want: "0001-01-01T00:00:00Z foo<bar>: hello",
		},
		{
			opt: Options{
				Subject: true,
				Reply:   true,
			},
			want: "foo<bar>: hello",
		},
		{
			opt: Options{
				Subject: true,
			},
			want: "foo: hello",
		},
		{
			opt: Options{
				Reply: true,
			},
			want: "<bar>: hello",
		},
		{
			opt: Options{
				Timestamp: true,
			},
			want: "0001-01-01T00:00:00Z: hello",
		},
		{
			opt: Options{
				Timestamp: true,
				Reply:     true,
			},
			want: "0001-01-01T00:00:00Z <bar>: hello",
		},
		{
			opt:  Options{},
			want: "hello",
		},
	}

	for _, c := range cases {
		s := Format(d, c.opt)
		if s != c.want {
			t.Fatalf("got=%q; want=%q", s, c.want)
		}
	}

}
