// Package capture wraps a shell process in a pty and records all I/O to the
// event store. The operator sees their normal terminal — wraith is invisible.
package capture

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/jallphin/wraith/internal/store"
)

// Run starts cmd inside a pty, mirrors I/O to the operator's terminal, and
// streams every byte written to stdin/stdout into the event store.
func Run(cmd *exec.Cmd, db *store.DB) error {
	// Start the command in a pty
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer ptmx.Close()

	// Handle terminal resize
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)
	go func() {
		for range sigwinch {
			if sz, err := pty.GetsizeFull(os.Stdin); err == nil {
				_ = pty.Setsize(ptmx, sz)
			}
		}
	}()
	// Set initial size
	if sz, err := pty.GetsizeFull(os.Stdin); err == nil {
		_ = pty.Setsize(ptmx, sz)
	}

	// Put terminal in raw mode
	oldState, err := pty.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	defer pty.Restore(int(os.Stdin.Fd()), oldState)

	// stdin → pty (capture input)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				ptmx.Write(data)
				db.WriteEvent(store.Event{
					Kind:      store.EventInput,
					Timestamp: time.Now(),
					Data:      data,
				})
			}
			if err != nil {
				break
			}
		}
	}()

	// pty → stdout (capture output)
	buf := make([]byte, 4096)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			os.Stdout.Write(data)
			db.WriteEvent(store.Event{
				Kind:      store.EventOutput,
				Timestamp: time.Now(),
				Data:      data,
			})
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}

	return cmd.Wait()
}
