package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/otterXf/otter/pkg/attestation"
	"github.com/otterXf/otter/pkg/compliance"
	"github.com/otterXf/otter/pkg/sbomindex"
	"github.com/otterXf/otter/pkg/storage"
	"github.com/otterXf/otter/pkg/vulnindex"
)

type ImageComplianceResponse struct {
	OrgID          string                       `json:"org_id"`
	ImageID        string                       `json:"image_id"`
	ImageName      string                       `json:"image_name"`
	StorageBackend string                       `json:"storage_backend"`
	ImageRef       string                       `json:"image_ref"`
	ScopeNote      string                       `json:"scope_note"`
	SourceRepo     *compliance.Repository       `json:"source_repository,omitempty"`
	SLSA           compliance.SLSAAssessment    `json:"slsa"`
	Scorecard      compliance.ScorecardSummary  `json:"scorecard"`
	Standards      []compliance.StandardSummary `json:"standards"`
	Summary        compliance.Summary           `json:"summary"`
	EvidenceErrors []string                     `json:"evidence_errors,omitempty"`
	UpdatedAt      string                       `json:"updated_at"`
}

func (h *ScanHandler) GetImageCompliance(c *gin.Context) {
	orgID, imageID, err := normalizeArtifactIDs(c.Query("org_id"), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !authorizeOrgRequest(c, orgID) {
		return
	}

	response, err := h.buildImageCompliance(c.Request.Context(), orgID, imageID)
	if err != nil {
		switch {
		case errors.Is(err, sbomindex.ErrNotFound), errors.Is(err, vulnindex.ErrNotFound), errors.Is(err, storage.ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "image compliance not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("load image compliance: %v", err)})
		}
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *ScanHandler) buildImageCompliance(ctx context.Context, orgID, imageID string) (ImageComplianceResponse, error) {
	imageRef, err := h.resolveStoredImageReference(ctx, orgID, imageID)
	if err != nil {
		return ImageComplianceResponse{}, err
	}

	var vulnerabilityInput *compliance.VulnerabilitySummary
	record, err := h.getExistingVulnerabilityRecord(ctx, orgID, imageID)
	if err != nil {
		return ImageComplianceResponse{}, fmt.Errorf("load vulnerability summary: %w", err)
	}
	if record != nil {
		vulnerabilityInput = &compliance.VulnerabilitySummary{
			Total:    record.Summary.Total,
			Critical: record.Summary.BySeverity["CRITICAL"],
			Fixable:  record.Summary.Fixable,
		}
	}

	var attestationInput *compliance.AttestationSummary
	var attestationErr error
	if h.attestor != nil {
		result, err := h.attestor.Discover(ctx, imageRef)
		if err != nil {
			attestationErr = err
		} else {
			attestationInput = buildComplianceAttestationSummary(result)
		}
	}

	assessment := h.compliance.Assess(ctx, compliance.Input{
		ImageRef:         imageRef,
		Vulnerabilities:  vulnerabilityInput,
		Attestations:     attestationInput,
		AttestationError: attestationErr,
	})

	return ImageComplianceResponse{
		OrgID:          orgID,
		ImageID:        imageID,
		ImageName:      imageRef,
		StorageBackend: h.store.Backend(),
		ImageRef:       assessment.ImageRef,
		ScopeNote:      assessment.ScopeNote,
		SourceRepo:     assessment.SourceRepository,
		SLSA:           assessment.SLSA,
		Scorecard:      assessment.Scorecard,
		Standards:      assessment.Standards,
		Summary:        assessment.Summary,
		EvidenceErrors: assessment.EvidenceErrors,
		UpdatedAt:      assessment.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}

func buildComplianceAttestationSummary(result attestation.Result) *compliance.AttestationSummary {
	records := append([]attestation.Record{}, result.Signatures...)
	records = append(records, result.Attestations...)

	provenance := make([]compliance.ProvenanceRecord, 0, len(result.Attestations))
	verified := false
	for _, record := range records {
		if record.VerificationStatus == attestation.VerificationStatusValid {
			verified = true
		}
	}
	for _, record := range result.Attestations {
		if record.Provenance == nil && record.PredicateType == "" {
			continue
		}
		provenance = append(provenance, compliance.ProvenanceRecord{
			BuilderID:           provenanceField(record, func(value *attestation.ProvenanceSummary) string { return value.BuilderID }),
			BuildType:           provenanceField(record, func(value *attestation.ProvenanceSummary) string { return value.BuildType }),
			InvocationID:        provenanceField(record, func(value *attestation.ProvenanceSummary) string { return value.InvocationID }),
			Materials:           provenanceMaterials(record),
			VerificationStatus:  record.VerificationStatus,
			PredicateType:       record.PredicateType,
			SourceRepositoryURL: firstSubjectName(record.Subjects),
		})
	}

	return &compliance.AttestationSummary{
		UpdatedAt:    result.UpdatedAt,
		Total:        result.Summary.Total,
		Signatures:   result.Summary.Signatures,
		Attestations: provenance,
		Verified:     verified,
	}
}

func firstSubjectName(subjects []attestation.StatementSubject) string {
	for _, subject := range subjects {
		if subject.Name != "" {
			return subject.Name
		}
	}
	return ""
}

func provenanceField(record attestation.Record, extractor func(*attestation.ProvenanceSummary) string) string {
	if record.Provenance == nil {
		return ""
	}
	return extractor(record.Provenance)
}

func provenanceMaterials(record attestation.Record) []string {
	if record.Provenance == nil {
		return nil
	}
	return append([]string(nil), record.Provenance.Materials...)
}
