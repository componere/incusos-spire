package attestor_test

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/componere/incusos-spire/internal/attestor"
	"github.com/componere/incusos-spire/internal/attestor/mocks"
)

const (
	capturedUUID       attestor.InstanceUUID     = "e9e6a2a0-d695-42d3-8e8c-92d290bfc7da"
	capturedGeneration attestor.GenerationUUID   = "74957ed8-19bc-4d23-b76b-763bb6f8bb60"
	capturedProject    attestor.ProjectName      = "spike-uuid-lab"
	capturedName       attestor.InstanceName     = "lab-c1r"
	capturedImage      attestor.ImageFingerprint = "f005c3b83cc4ffe5b0e0a0c3fccdee6decbae5559fafce9861d9c8b3d2720a16"
	cloneUUID          attestor.InstanceUUID     = "8143228f-fa57-4c09-bae1-5bf3f227cb89"
	cloneGeneration    attestor.GenerationUUID   = "8143228f-fa57-4c09-bae1-5bf3f227cb89"
	restoreGeneration  attestor.GenerationUUID   = "50dd028f-da77-4f87-83e8-0773c72cbc05"
	ambiguousUUID      attestor.InstanceUUID     = "f09e831b-fd6a-40fa-928a-d13c35d5959e"
	ambiguousCount                               = 2
	serverName                                   = "ns1001912.ip-147-135-105.us"
	serverFingerprint                            = "822b00ed474a2574d43223cbf34919b76a64946e145ec246aa4ae2e43318afdd"
	selectorUUID                                 = 0
	selectorGeneration                           = 1
	selectorName                                 = 4
)

func capturedRecord() attestor.InstanceRecord {
	return attestor.InstanceRecord{
		UUID:       capturedUUID,
		Generation: capturedGeneration,
		Project:    capturedProject,
		Type:       attestor.InstanceTypeContainer,
		Status:     attestor.InstanceStatusRunning,
		Location:   "none",
		Image:      capturedImage,
		Name:       capturedName,
		CreatedAt:  "2026-08-16T23:32:37.236591866Z",
	}
}

func capturedReference() attestor.Reference {
	return attestor.Reference{InstanceUUID: capturedUUID}
}

func capturedEndpoint() attestor.EndpointIdentity {
	return attestor.EndpointIdentity{
		ServerName:             serverName,
		CertificateFingerprint: serverFingerprint,
	}
}

func expectedSelectors(record attestor.InstanceRecord) []attestor.Selector {
	return []attestor.Selector{
		attestor.Selector("incus:uuid:" + string(record.UUID)),
		attestor.Selector("incus:generation:" + string(record.Generation)),
		attestor.Selector("incus:project:" + string(record.Project)),
		attestor.Selector("incus:type:" + string(record.Type)),
		attestor.Selector("incus:name:" + string(record.Name)),
		attestor.Selector("incus:image:" + string(record.Image)),
	}
}

func TestSelectorTypeAndValue(t *testing.T) {
	t.Parallel()

	typeName, value := attestor.Selector("incus:uuid:" + string(capturedUUID)).TypeAndValue()
	require.Equal(t, "incus", typeName)
	require.Equal(t, "uuid:"+string(capturedUUID), value)
}

func TestDeriveEmitsExactFrozenSelectors(t *testing.T) {
	t.Parallel()

	reader := mocks.NewMockInstanceReader(t)
	record := capturedRecord()
	ref := capturedReference()
	reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, ref.InstanceUUID, ref.Project).
		Return(record, nil).
		Once()

	got, err := attestor.NewDeriver(reader).Derive(t.Context(), ref)
	require.NoError(t, err)
	require.Equal(t, expectedSelectors(record), got)
	assertRejectedSelectorsAbsent(t, got)
	reader.AssertNotCalled(t, "ReadEndpointIdentity", mock.Anything)
}

func TestDeriveRenameChangesOnlyName(t *testing.T) {
	t.Parallel()

	beforeRecord := capturedRecord()
	beforeRecord.Name = "lab-c1"
	afterRecord := capturedRecord()
	afterRecord.Name = capturedName

	before := deriveRecord(t, beforeRecord)
	after := deriveRecord(t, afterRecord)
	requireOnlyIndexesDiffer(t, before, after, selectorName)
}

func TestDeriveCloneChangesOnlyUUIDAndGeneration(t *testing.T) {
	t.Parallel()

	source := capturedRecord()
	clone := capturedRecord()
	clone.UUID = cloneUUID
	clone.Generation = cloneGeneration

	before := deriveRecord(t, source)
	after := deriveRecord(t, clone)
	requireOnlyIndexesDiffer(t, before, after, selectorUUID, selectorGeneration)
}

func TestDeriveRestoreChangesOnlyGeneration(t *testing.T) {
	t.Parallel()

	beforeRecord := capturedRecord()
	afterRecord := capturedRecord()
	afterRecord.Generation = restoreGeneration

	before := deriveRecord(t, beforeRecord)
	after := deriveRecord(t, afterRecord)
	requireOnlyIndexesDiffer(t, before, after, selectorGeneration)
}

func TestDeriveTrustRules(t *testing.T) {
	t.Parallel()

	backendErr := errors.New("connection refused")
	tests := []struct {
		name       string
		ref        attestor.Reference
		opts       []attestor.Option
		setup      func(t *testing.T, reader *mocks.MockInstanceReader)
		idleReader bool
		wantErr    error
		notErr     error
		wantMsg    string
	}{
		{
			name:       "empty instance uuid is invalid and never a wildcard",
			ref:        attestor.Reference{},
			idleReader: true,
			wantErr:    attestor.ErrInvalidReference,
		},
		{
			name:       "non-canonical instance uuid is invalid",
			ref:        attestor.Reference{InstanceUUID: "NOT-A-UUID"},
			idleReader: true,
			wantErr:    attestor.ErrInvalidReference,
		},
		{
			name:       "uppercase uuid is not canonical",
			ref:        attestor.Reference{InstanceUUID: attestor.InstanceUUID(strings.ToUpper(string(capturedUUID)))},
			idleReader: true,
			wantErr:    attestor.ErrInvalidReference,
		},
		{
			name: "not found is distinguishable from backend error",
			ref:  capturedReference(),
			setup: func(t *testing.T, reader *mocks.MockInstanceReader) {
				t.Helper()
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
					Return(attestor.InstanceRecord{}, attestor.ErrInstanceNotFound).
					Once()
			},
			wantErr: attestor.ErrInstanceNotFound,
			notErr:  attestor.ErrBackendUnavailable,
		},
		{
			name: "backend transport failure wraps ErrBackendUnavailable",
			ref:  capturedReference(),
			setup: func(t *testing.T, reader *mocks.MockInstanceReader) {
				t.Helper()
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
					Return(attestor.InstanceRecord{}, backendErr).
					Once()
			},
			wantErr: attestor.ErrBackendUnavailable,
			notErr:  attestor.ErrInstanceNotFound,
		},
		{
			name: "ambiguous reference fails with match count and never picks a record",
			ref:  attestor.Reference{InstanceUUID: ambiguousUUID},
			setup: func(t *testing.T, reader *mocks.MockInstanceReader) {
				t.Helper()
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, ambiguousUUID, attestor.ProjectName("")).
					Return(attestor.InstanceRecord{}, fmt.Errorf(
						"attestor: %d instances matched uuid %s: %w",
						ambiguousCount,
						ambiguousUUID,
						attestor.ErrAmbiguousReference,
					)).
					Once()
			},
			wantErr: attestor.ErrAmbiguousReference,
			wantMsg: "2",
		},
		{
			name: "empty volatile.uuid is unusable",
			ref:  capturedReference(),
			setup: func(t *testing.T, reader *mocks.MockInstanceReader) {
				t.Helper()
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
					Return(attestor.InstanceRecord{Status: attestor.InstanceStatusRunning}, nil).
					Once()
			},
			wantErr: attestor.ErrUnusableRecord,
		},
		{
			name: "record uuid that does not equal the requested uuid is unusable",
			ref:  capturedReference(),
			setup: func(t *testing.T, reader *mocks.MockInstanceReader) {
				t.Helper()
				mismatched := capturedRecord()
				mismatched.UUID = cloneUUID
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
					Return(mismatched, nil).
					Once()
			},
			wantErr: attestor.ErrUnusableRecord,
		},
		{
			name: "generation mismatch is a hard failure",
			ref: attestor.Reference{
				InstanceUUID: capturedUUID,
				Generation:   restoreGeneration,
			},
			setup: func(t *testing.T, reader *mocks.MockInstanceReader) {
				t.Helper()
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
					Return(capturedRecord(), nil).
					Once()
			},
			wantErr: attestor.ErrGenerationMismatch,
		},
		{
			name: "project expectation mismatch is unusable",
			ref: attestor.Reference{
				InstanceUUID: capturedUUID,
				Project:      "default",
			},
			setup: func(t *testing.T, reader *mocks.MockInstanceReader) {
				t.Helper()
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("default")).
					Return(capturedRecord(), nil).
					Once()
			},
			wantErr: attestor.ErrUnusableRecord,
		},
		{
			name: "endpoint mismatch fails",
			ref: attestor.Reference{
				InstanceUUID: capturedUUID,
				Server:       "other-incus",
			},
			setup: func(t *testing.T, reader *mocks.MockInstanceReader) {
				t.Helper()
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
					Return(capturedRecord(), nil).
					Once()
				reader.EXPECT().
					ReadEndpointIdentity(mock.Anything).
					Return(capturedEndpoint(), nil).
					Once()
			},
			wantErr: attestor.ErrEndpointMismatch,
		},
		{
			name: "non-Running status fails under the default policy",
			ref:  capturedReference(),
			setup: func(t *testing.T, reader *mocks.MockInstanceReader) {
				t.Helper()
				stopped := capturedRecord()
				stopped.Status = attestor.InstanceStatusStopped
				reader.EXPECT().
					ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
					Return(stopped, nil).
					Once()
			},
			wantErr: attestor.ErrUnusableRecord,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			reader := mocks.NewMockInstanceReader(t)
			if tc.setup != nil {
				tc.setup(t, reader)
			}

			got, err := attestor.NewDeriver(reader, tc.opts...).Derive(t.Context(), tc.ref)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, got)
			if tc.notErr != nil {
				require.NotErrorIs(t, err, tc.notErr)
			}
			if tc.wantMsg != "" {
				require.ErrorContains(t, err, tc.wantMsg)
			}
			if tc.idleReader {
				reader.AssertNotCalled(t, "ReadInstanceByUUID", mock.Anything, mock.Anything, mock.Anything)
				reader.AssertNotCalled(t, "ReadEndpointIdentity", mock.Anything)
			}
		})
	}
}

func TestDeriveCallsReadEndpointIdentityOnlyWhenServerSet(t *testing.T) {
	t.Parallel()

	t.Run("server empty does not call endpoint identity", func(t *testing.T) {
		t.Parallel()

		reader := mocks.NewMockInstanceReader(t)
		reader.EXPECT().
			ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
			Return(capturedRecord(), nil).
			Once()

		_, err := attestor.NewDeriver(reader).Derive(t.Context(), capturedReference())
		require.NoError(t, err)
		reader.AssertNotCalled(t, "ReadEndpointIdentity", mock.Anything)
	})

	t.Run("server name match calls endpoint identity once", func(t *testing.T) {
		t.Parallel()

		reader := mocks.NewMockInstanceReader(t)
		ref := capturedReference()
		ref.Server = serverName
		reader.EXPECT().
			ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
			Return(capturedRecord(), nil).
			Once()
		reader.EXPECT().
			ReadEndpointIdentity(mock.Anything).
			Return(capturedEndpoint(), nil).
			Once()

		got, err := attestor.NewDeriver(reader).Derive(t.Context(), ref)
		require.NoError(t, err)
		require.Equal(t, expectedSelectors(capturedRecord()), got)
	})

	t.Run("certificate fingerprint match calls endpoint identity once", func(t *testing.T) {
		t.Parallel()

		reader := mocks.NewMockInstanceReader(t)
		ref := capturedReference()
		ref.Server = serverFingerprint
		reader.EXPECT().
			ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
			Return(capturedRecord(), nil).
			Once()
		reader.EXPECT().
			ReadEndpointIdentity(mock.Anything).
			Return(capturedEndpoint(), nil).
			Once()

		got, err := attestor.NewDeriver(reader).Derive(t.Context(), ref)
		require.NoError(t, err)
		require.Equal(t, expectedSelectors(capturedRecord()), got)
	})
}

func TestDeriveAllowsConfiguredStatuses(t *testing.T) {
	t.Parallel()

	reader := mocks.NewMockInstanceReader(t)
	stopped := capturedRecord()
	stopped.Status = attestor.InstanceStatusStopped
	reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, capturedUUID, attestor.ProjectName("")).
		Return(stopped, nil).
		Once()

	got, err := attestor.NewDeriver(reader, attestor.WithAllowedStatuses(attestor.InstanceStatusStopped)).
		Derive(t.Context(), capturedReference())
	require.NoError(t, err)
	require.Equal(t, expectedSelectors(stopped), got)
}

func TestPackageImportsStayPure(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fileSet := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		path := filepath.Join(".", entry.Name())
		file, parseErr := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		require.NoError(t, parseErr, path)

		for _, spec := range file.Imports {
			importPath := strings.Trim(spec.Path.Value, `"`)
			require.NotEqual(t, "net/http", importPath, path)
			require.NotEqual(t, "time", importPath, path)
			require.NotContains(t, importPath, "github.com/lxc", path)
			require.NotContains(t, importPath, "incus", path)
		}
	}
}

func deriveRecord(t *testing.T, record attestor.InstanceRecord) []attestor.Selector {
	t.Helper()

	reader := mocks.NewMockInstanceReader(t)
	ref := attestor.Reference{InstanceUUID: record.UUID}
	reader.EXPECT().
		ReadInstanceByUUID(mock.Anything, record.UUID, attestor.ProjectName("")).
		Return(record, nil).
		Once()

	got, err := attestor.NewDeriver(reader).Derive(t.Context(), ref)
	require.NoError(t, err)
	reader.AssertNotCalled(t, "ReadEndpointIdentity", mock.Anything)

	return got
}

func requireOnlyIndexesDiffer(t *testing.T, before, after []attestor.Selector, indexes ...int) {
	t.Helper()
	require.Len(t, after, len(before))

	mustDiffer := make(map[int]struct{}, len(indexes))
	for _, index := range indexes {
		mustDiffer[index] = struct{}{}
	}

	for index := range before {
		if _, ok := mustDiffer[index]; ok {
			require.NotEqual(t, before[index], after[index], "selector %d should change", index)
			continue
		}

		require.Equal(t, before[index], after[index], "selector %d should be unchanged", index)
	}
}

func assertRejectedSelectorsAbsent(t *testing.T, selectors []attestor.Selector) {
	t.Helper()

	rejected := []string{
		"incus:status:",
		"incus:location:",
		"incus:server:",
		"incus:cloudinit-id:",
		"incus:created-at:",
	}
	for _, got := range selectors {
		for _, prefix := range rejected {
			require.False(t, strings.HasPrefix(string(got), prefix), "emitted rejected selector %s", got)
		}
	}
}
