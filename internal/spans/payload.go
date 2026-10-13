// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"encoding/json"
	"errors"

	"github.com/DataDog/dd-iast-go/internal/model"
)

const (
	// MaxEventPayloadBytes is the maximum accepted actual event encoding size.
	MaxEventPayloadBytes = 25_000
	// MaxSizeExceededEvidence is the compatibility sentinel used when detailed
	// evidence does not fit the payload budget.
	MaxSizeExceededEvidence = "MAX_SIZE_EXCEEDED"
)

// PayloadEncoding selects the event encoding whose actual size is checked.
type PayloadEncoding uint8

const (
	PayloadEncodingMsgpack PayloadEncoding = iota
	PayloadEncodingJSON
)

// LimitedPayload is a fully encoded event and the event used to produce it.
// Event is the input pointer when no degradation was required; Encoded remains
// authoritative and callers must keep a shared input locked and unmodified.
type LimitedPayload struct {
	Event     *model.Event
	Encoded   []byte
	Truncated bool
}

var (
	errInvalidPayloadEvent    = errors.New("invalid IAST payload event")
	errInvalidPayloadEncoding = errors.New("invalid IAST payload encoding")
	errPayloadLimitExceeded   = errors.New("IAST fallback payload exceeds hard limit")
)

// BuildLimitedPayload encodes event on the selected path and returns a separate
// bounded fallback if its actual encoding exceeds MaxEventPayloadBytes. It does
// not mutate event. A caller that shares event must hold its exclusive lock for
// the complete call. Event may be handed to a deferred encoder only after the
// caller has made the shared input permanently immutable.
func BuildLimitedPayload(event *model.Event, encoding PayloadEncoding) (LimitedPayload, error) {
	if event == nil || len(event.Vulnerabilities) > model.MaxVulnerabilities {
		return LimitedPayload{}, errInvalidPayloadEvent
	}
	encoded, err := encodePayloadEvent(event, encoding)
	if err != nil {
		return LimitedPayload{}, err
	}
	if len(encoded) <= MaxEventPayloadBytes {
		return LimitedPayload{Event: event, Encoded: encoded}, nil
	}

	fallback := fallbackEvent(event, false, false)
	encoded, err = encodePayloadEvent(fallback, encoding)
	if err != nil {
		return LimitedPayload{}, err
	}
	if len(encoded) > MaxEventPayloadBytes {
		fallback = fallbackEvent(event, true, false)
		encoded, err = encodePayloadEvent(fallback, encoding)
		if err != nil {
			return LimitedPayload{}, err
		}
	}
	if len(encoded) > MaxEventPayloadBytes {
		fallback = fallbackEvent(event, true, true)
		encoded, err = encodePayloadEvent(fallback, encoding)
		if err != nil {
			return LimitedPayload{}, err
		}
	}
	if len(encoded) > MaxEventPayloadBytes {
		return LimitedPayload{}, errPayloadLimitExceeded
	}
	return LimitedPayload{Event: fallback, Encoded: encoded, Truncated: true}, nil
}

func encodePayloadEvent(event *model.Event, encoding PayloadEncoding) ([]byte, error) {
	switch encoding {
	case PayloadEncodingMsgpack:
		return event.MarshalMsg(nil)
	case PayloadEncodingJSON:
		return json.Marshal(event)
	default:
		return nil, errInvalidPayloadEncoding
	}
}

func fallbackEvent(event *model.Event, stripLocationStrings, stripStackID bool) *model.Event {
	fallback := &model.Event{Vulnerabilities: make([]model.Vulnerability, len(event.Vulnerabilities))}
	for index, vulnerability := range event.Vulnerabilities {
		fallbackVulnerability := model.Vulnerability{
			Type:     vulnerability.Type,
			Hash:     vulnerability.Hash,
			Evidence: &model.Evidence{Value: MaxSizeExceededEvidence},
		}
		if vulnerability.Location != nil {
			location := *vulnerability.Location
			if stripLocationStrings {
				location.Path = ""
				location.Class = ""
				location.Method = ""
			}
			if stripStackID {
				location.StackID = ""
			}
			fallbackVulnerability.Location = &location
		}
		fallback.Vulnerabilities[index] = fallbackVulnerability
	}
	return fallback
}
