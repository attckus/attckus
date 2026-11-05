package gateway

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// MaxMessage bounds one JSON-RPC message.
const MaxMessage = 16 << 20

// lockedWriter serialises newline-terminated writes from several goroutines.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) writeLine(b []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(b); err != nil {
		return err
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		_, err := l.w.Write([]byte{'\n'})
		return err
	}
	return nil
}

// ServeStdio relays newline-delimited JSON-RPC between an agent (clientIn,
// clientOut) and a server (serverIn, serverOut). It returns when the server's
// output ends or ctx is cancelled. serverIn is closed once the client's input
// ends and every delayed message has been delivered.
func ServeStdio(ctx context.Context, e *Engine, clientIn io.Reader, clientOut io.Writer, serverIn io.WriteCloser, serverOut io.Reader) error {
	toClient := &lockedWriter{w: clientOut}
	toServer := &lockedWriter{w: serverIn}
	var delayed sync.WaitGroup

	apply := func(o Outcome) {
		if o.Forward != nil {
			_ = toServer.writeLine(o.Forward)
		}
		if o.Reply != nil {
			_ = toClient.writeLine(o.Reply)
		}
	}

	clientDone := make(chan error, 1)
	go func() {
		err := readLines(clientIn, func(line []byte) {
			o := e.FromClient("", "", line)
			if o.Delay <= 0 {
				apply(o)
				return
			}
			delayed.Add(1)
			go func() {
				defer delayed.Done()
				select {
				case <-time.After(o.Delay):
					apply(o)
				case <-ctx.Done():
				}
			}()
		})
		delayed.Wait()
		_ = serverIn.Close()
		clientDone <- err
	}()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- readLines(serverOut, func(line []byte) {
			_ = toClient.writeLine(e.FromServer("", line))
		})
	}()

	select {
	case err := <-serverDone:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// readLines calls fn for each non-empty line until EOF.
func readLines(r io.Reader, fn func([]byte)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := readLine(br)
		if len(line) > 0 {
			fn(line)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

var errTooLong = errors.New("gateway: message exceeds 16 MiB")

func readLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		buf = append(buf, chunk...)
		if len(buf) > MaxMessage {
			return nil, errTooLong
		}
		if err != nil {
			return buf, err
		}
		if !isPrefix {
			return buf, nil
		}
	}
}
