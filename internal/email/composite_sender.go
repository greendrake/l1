package email

import (
	"context"
	"fmt"
	"strings"
)

// CompositeEmailSender implements the Sender interface and delegates sending to multiple Senders.
type CompositeEmailSender struct {
	senders []Sender
}

// NewCompositeEmailSender creates a new CompositeEmailSender.
// It now returns the concrete type *CompositeEmailSender to allow AddSender to be called directly.
func NewCompositeEmailSender(senders ...Sender) *CompositeEmailSender {
	return &CompositeEmailSender{senders: senders}
}

// AddSender adds a sender to the composite sender's list.
func (cs *CompositeEmailSender) AddSender(sender Sender) {
	if sender != nil {
		cs.senders = append(cs.senders, sender)
	}
}

// Send iterates through all registered senders and calls their Send method.
// It collects all errors encountered and returns them as a single error.
func (cs *CompositeEmailSender) Send(ctx context.Context, to []string, subject string, rawMessage []byte) error {
	if len(cs.senders) == 0 {
		return fmt.Errorf("no senders configured in CompositeEmailSender")
	}

	var allErrors []string
	for _, sender := range cs.senders {
		if err := sender.Send(ctx, to, subject, rawMessage); err != nil {
			allErrors = append(allErrors, err.Error())
		}
	}

	if len(allErrors) > 0 {
		return fmt.Errorf("composite email send failed: [ %s ]", strings.Join(allErrors, "; "))
	}
	return nil
}
