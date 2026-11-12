package app

import (
	"context"
	"errors"

	"latch.local/client/internal/network"
)

// Run serializes inputs and network events. The caller closes the terminal after
// Run returns so raw mode is restored before printing any error diagnostics.
func Run(ctx context.Context, model *Model, connection *network.Connection, inputs <-chan Command, render func(Snapshot)) error {
	defer model.Close()
	defer connection.Close()
	render(model.Snapshot())
	for {
		select {
		case <-ctx.Done():
			return nil
		case command, ok := <-inputs:
			if command.Err != nil {
				return command.Err
			}
			if !ok || command.Quit {
				return nil
			}
			if command.Cancel {
				model.CancelSecret()
				render(model.Snapshot())
				continue
			}
			err := model.Input(command.Text)
			if errors.Is(err, ErrQuit) {
				return nil
			}
			if err != nil {
				return err
			}
			render(model.Snapshot())
		case event, ok := <-connection.Events():
			if !ok || event.Err != nil {
				model.Disconnected()
				render(model.Snapshot())
				return network.ErrClosed
			}
			err := model.Handle(event.Message)
			if errors.Is(err, ErrQuit) {
				return nil
			}
			if err != nil {
				return err
			}
			render(model.Snapshot())
		}
	}
}

type Command struct {
	Text         string
	Cancel, Quit bool
	Err          error
}
