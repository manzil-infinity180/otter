package api

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/otterXf/otter/pkg/attestation"
	"github.com/otterXf/otter/pkg/policy"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

func (h *ScanHandler) SetPolicyEngine(engine *policy.Engine) {
	if engine == nil {
		engine = policy.NewDisabledEngine()
	}
	h.policy = engine
}

func (h *ScanHandler) evaluatePolicy(ctx context.Context, orgID, imageID, imageName string, vulnerabilities *vulnindex.Record, discovered *attestation.Result, discoverErr error) policy.Evaluation {
	engine := h.policy
	if engine == nil {
		engine = policy.NewDisabledEngine()
	}

	input := policy.Input{
		OrgID:     strings.TrimSpace(orgID),
		ImageID:   strings.TrimSpace(imageID),
		ImageName: strings.TrimSpace(imageName),
	}
	if vulnerabilities != nil {
		input.Vulnerabilities = *vulnerabilities
	}

	if engine.RequiresAttestations() {
		if discovered == nil && discoverErr == nil && input.ImageName != "" {
			result, err := h.attestor.Discover(ctx, input.ImageName)
			if err != nil {
				discoverErr = err
			} else {
				discovered = &result
			}
		}
		if discovered != nil {
			input.Attestations = discovered
		}
		if discoverErr != nil {
			input.AttestationError = discoverErr.Error()
		} else if input.ImageName == "" && discovered == nil {
			input.AttestationError = "image reference unavailable for attestation discovery"
		}
	}

	return engine.Evaluate(input)
}

func writePolicyHeaders(headers headerWriter, evaluation policy.Evaluation) {
	if headers == nil {
		return
	}
	headers.Set("X-Otter-Policy-Mode", evaluation.Mode)
	headers.Set("X-Otter-Policy-Status", evaluation.Status)
	headers.Set("X-Otter-Policy-Allowed", strconv.FormatBool(evaluation.Allowed))
}

type headerWriter interface {
	Set(string, string)
}

func (h *ScanHandler) loadPolicyVulnerabilityRecord(ctx context.Context, orgID, imageID string) (*vulnindex.Record, error) {
	record, err := h.getOrBuildVulnerabilityRecord(ctx, orgID, imageID)
	if err == nil {
		return &record, nil
	}
	if errors.Is(err, storage.ErrNotFound) || errors.Is(err, vulnindex.ErrNotFound) {
		return nil, nil
	}
	return nil, err
}
