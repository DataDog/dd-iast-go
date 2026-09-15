// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

const (
	// MaxEventSources bounds exact source identities retained by one annotation.
	MaxEventSources = 256
	// MaxEventSourceBytes bounds complete exact source identity strings retained
	// by one annotation until span finish.
	MaxEventSourceBytes = 256 << 10
	// MaxProcessEventSourceBytes bounds exact source identity strings across all
	// live annotations.
	MaxProcessEventSourceBytes = 2 << 20
	// MaxEventVulnerabilities is the non-configurable event vulnerability bound.
	MaxEventVulnerabilities = model.MaxVulnerabilities
)

var processEventSourceBytes atomic.Int64

// SourceIdentity is one complete unredacted event source identity.
type SourceIdentity struct {
	Origin constants.Origin
	Name   string
	Value  string
}

// TaintedSource pairs exact de-duplication identity with its wire model.
type TaintedSource struct {
	Identity SourceIdentity
	Model    model.Source
}

// TaintedCommit is one locally indexed vulnerability and its source table.
// Every ValuePart source index must refer to Sources. Vulnerability.Hash must
// be final before the transaction starts.
type TaintedCommit struct {
	Vulnerability model.Vulnerability
	Sources       []TaintedSource
}

// TryCommitTainted transactionally merges sources and vulnerability into a
// sampled open annotation. beforeCommit runs with the annotation locked after
// all bounds are reserved and receives the private vulnerability copy that will
// be published. It must not re-lock or finish the annotation. A callback panic
// is recovered, logged, and rolls the transaction back. The method returns
// false on invalid input, contention, closure, duplication, or capacity.
// +checklocksignore
func (a *Annotation) TryCommitTainted(commit *TaintedCommit, beforeCommit func(*model.Vulnerability)) (committed bool) {
	if a == nil || commit == nil || !a.Sampled || len(commit.Sources) > MaxEventSources {
		return false
	}
	if !a.RWMutex.TryLock() {
		return false
	}
	defer a.RWMutex.Unlock() // +checklocksforce: TryLock.
	if a.closed.Load() || !a.Event.CanAddVulnerability(commit.Vulnerability) {
		return false
	}
	if len(a.Event.Sources) != len(a.sourceIdentities) {
		instrumentation.Instance.TelemetryLog().Warn("iast source identity sidecar is inconsistent")
		return false
	}

	index := a.sourceIndex
	mapping := make([]int, len(commit.Sources))
	newSources := make([]int, 0, len(commit.Sources))
	pendingIdentities := make([]SourceIdentity, 0, len(commit.Sources))
	additionalBytes := int64(0)
	for localIndex, candidate := range commit.Sources {
		eventIndex, exists := a.findSource(index[:], candidate.Identity, pendingIdentities)
		if !exists {
			if len(a.sourceIdentities)+len(newSources) >= MaxEventSources {
				return false
			}
			remaining := int64(MaxEventSourceBytes) - a.sourceIdentityBytes - additionalBytes
			if remaining < 0 || int64(len(candidate.Identity.Name)) > remaining {
				return false
			}
			remaining -= int64(len(candidate.Identity.Name))
			if int64(len(candidate.Identity.Value)) > remaining {
				return false
			}
			eventIndex = len(a.sourceIdentities) + len(newSources)
			if !insertSourceIndex(index[:], candidate.Identity, eventIndex) {
				return false
			}
			newSources = append(newSources, localIndex)
			pendingIdentities = append(pendingIdentities, candidate.Identity)
			additionalBytes += int64(len(candidate.Identity.Name)) + int64(len(candidate.Identity.Value))
		}
		mapping[localIndex] = eventIndex
	}

	for _, eventIndex := range mapping {
		a.eventSourceIndexes[eventIndex] = eventIndex
	}
	vulnerability := commit.Vulnerability
	if vulnerability.Location != nil {
		location := *vulnerability.Location
		vulnerability.Location = &location
	}
	parts, ok := a.remapParts(vulnerability.Evidence, mapping)
	if !ok {
		return false
	}
	if vulnerability.Evidence != nil {
		evidence := *vulnerability.Evidence
		evidence.ValueParts = parts
		vulnerability.Evidence = &evidence
	}
	stagedIdentities := append(make([]SourceIdentity, 0, len(a.sourceIdentities)+len(newSources)), a.sourceIdentities...)
	stagedModels := append(make([]model.Source, 0, len(a.Event.Sources)+len(newSources)), a.Event.Sources...)
	for _, localIndex := range newSources {
		stagedIdentities = append(stagedIdentities, commit.Sources[localIndex].Identity)
		stagedModels = append(stagedModels, commit.Sources[localIndex].Model)
	}
	var redacted [MaxEventSources]bool
	for localIndex, candidate := range commit.Sources {
		eventIndex := mapping[localIndex]
		if candidate.Model.Redacted && !stagedModels[eventIndex].Redacted {
			stagedModels[eventIndex] = candidate.Model
		}
		redacted[eventIndex] = stagedModels[eventIndex].Redacted
	}
	stagedVulnerabilities := redactSourceOccurrences(a.Event.Vulnerabilities, redacted)
	vulnerability = redactSourceOccurrence(vulnerability, redacted)

	if !reserveEventSourceBytes(additionalBytes) {
		return false
	}
	reserved := additionalBytes
	defer func() {
		if recovered := recover(); recovered != nil {
			instrumentation.Instance.TelemetryLog().Warn("recovered panic while committing tainted vulnerability", slog.Any("panic", recovered))
			committed = false
		}
		if !committed {
			processEventSourceBytes.Add(-reserved)
		}
	}()
	if beforeCommit != nil {
		beforeCommit(&vulnerability)
	}
	stagedVulnerabilities = append(stagedVulnerabilities, vulnerability)

	a.sourceIdentities = stagedIdentities
	a.Event.Sources = stagedModels
	a.Event.Vulnerabilities = stagedVulnerabilities
	a.sourceIdentityBytes += additionalBytes
	a.sourceIndex = index
	committed = true
	return true
}

// +checklocks:a.RWMutex
func (a *Annotation) findSource(index []uint16, identity SourceIdentity, pending []SourceIdentity) (int, bool) {
	slot := int(sourceIdentityHash(identity) % uint64(len(index)))
	for range len(index) {
		encoded := index[slot]
		if encoded == 0 {
			return 0, false
		}
		candidateIndex := int(encoded - 1)
		if candidateIndex < len(a.sourceIdentities) {
			if a.sourceIdentities[candidateIndex] == identity {
				return candidateIndex, true
			}
		} else {
			pendingIndex := candidateIndex - len(a.sourceIdentities)
			if pendingIndex < len(pending) && pending[pendingIndex] == identity {
				return candidateIndex, true
			}
		}
		slot++
		if slot == len(index) {
			slot = 0
		}
	}
	return 0, false
}

func insertSourceIndex(index []uint16, identity SourceIdentity, sourceIndex int) bool {
	slot := int(sourceIdentityHash(identity) % uint64(len(index)))
	for range len(index) {
		if index[slot] == 0 {
			index[slot] = uint16(sourceIndex + 1)
			return true
		}
		slot++
		if slot == len(index) {
			slot = 0
		}
	}
	return false
}

func sourceIdentityHash(identity SourceIdentity) uint64 {
	const (
		offset = uint64(14695981039346656037)
		prime  = uint64(1099511628211)
	)
	hash := (offset ^ uint64(identity.Origin)) * prime
	for index := 0; index < len(identity.Name); index++ {
		hash = (hash ^ uint64(identity.Name[index])) * prime
	}
	hash = (hash ^ 0xff) * prime
	for index := 0; index < len(identity.Value); index++ {
		hash = (hash ^ uint64(identity.Value[index])) * prime
	}
	return hash
}

func redactSourceOccurrences(vulnerabilities []model.Vulnerability, redacted [MaxEventSources]bool) []model.Vulnerability {
	result := append(make([]model.Vulnerability, 0, len(vulnerabilities)+1), vulnerabilities...)
	for index := range result {
		result[index] = redactSourceOccurrence(result[index], redacted)
	}
	return result
}

func redactSourceOccurrence(vulnerability model.Vulnerability, redacted [MaxEventSources]bool) model.Vulnerability {
	if vulnerability.Evidence == nil || len(vulnerability.Evidence.ValueParts) == 0 {
		return vulnerability
	}
	needsRedaction := false
	for index := range vulnerability.Evidence.ValueParts {
		part := &vulnerability.Evidence.ValueParts[index]
		if part.SourceIndex == nil || part.Redacted {
			continue
		}
		sourceIndex := *part.SourceIndex
		if sourceIndex >= 0 && sourceIndex < len(redacted) && redacted[sourceIndex] {
			needsRedaction = true
			break
		}
	}
	if !needsRedaction {
		return vulnerability
	}
	evidence := *vulnerability.Evidence
	parts := make([]model.ValuePart, len(evidence.ValueParts))
	copy(parts, evidence.ValueParts)
	for index := range parts {
		if parts[index].SourceIndex == nil {
			continue
		}
		sourceIndex := *parts[index].SourceIndex
		if sourceIndex < 0 || sourceIndex >= len(redacted) || !redacted[sourceIndex] || parts[index].Redacted {
			continue
		}
		parts[index].Pattern = strings.Repeat("*", len(parts[index].Value))
		parts[index].Value = ""
		parts[index].Redacted = true
	}
	evidence.ValueParts = parts
	vulnerability.Evidence = &evidence
	return vulnerability
}

// +checklocks:a.RWMutex
func (a *Annotation) remapParts(evidence *model.Evidence, mapping []int) ([]model.ValuePart, bool) {
	if evidence == nil {
		return nil, true
	}
	parts := make([]model.ValuePart, len(evidence.ValueParts))
	copy(parts, evidence.ValueParts)
	for partIndex := range parts {
		if len(parts[partIndex].SecureMarks) != 0 {
			parts[partIndex].SecureMarks = append([]constants.VulnerabilityType(nil), parts[partIndex].SecureMarks...)
		}
		if parts[partIndex].SourceIndex == nil {
			continue
		}
		local := *parts[partIndex].SourceIndex
		if local < 0 || local >= len(mapping) {
			return nil, false
		}
		eventIndex := mapping[local]
		parts[partIndex].SourceIndex = &a.eventSourceIndexes[eventIndex]
	}
	return parts, true
}

func reserveEventSourceBytes(amount int64) bool {
	if amount < 0 {
		return false
	}
	for {
		current := processEventSourceBytes.Load()
		if amount > MaxProcessEventSourceBytes-current {
			return false
		}
		if processEventSourceBytes.CompareAndSwap(current, current+amount) {
			return true
		}
	}
}

// +checklocks:a.RWMutex
func (a *Annotation) releaseSourceIdentities() {
	if a.sourceIdentityBytes != 0 {
		processEventSourceBytes.Add(-a.sourceIdentityBytes)
	}
	clear(a.sourceIdentities)
	a.sourceIdentities = nil
	a.sourceIdentityBytes = 0
	clear(a.sourceIndex[:])
}
