// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package substrate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestBuildActorTemplate_DataSnapshots(t *testing.T) {
	tmpl := BuildActorTemplate("test-ns", "test-template", "test-image", nil, nil, "s3://test-bucket/snapshots")
	sc := tmpl.GetSnapshotConfig()
	if sc.GetOnPause() != ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_DATA ||
		sc.GetOnCommit() != ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_DATA {
		t.Fatal("pause and commit must capture durable data")
	}
	if sc.GetStorageLocation() != "s3://test-bucket/snapshots" {
		t.Fatalf("unexpected snapshot storage location: %q", sc.GetStorageLocation())
	}
	if len(tmpl.GetVolumes()) != 1 || tmpl.GetVolumes()[0].GetDurableDir() == nil {
		t.Fatal("template must retain its durable workspace volume")
	}
	probe := tmpl.GetContainers()[0].GetWakeupProbe().GetHttpGet()
	if probe.GetPath() != "/readyz" || probe.GetPort() != 80 {
		t.Fatalf("unexpected wakeup probe: %v", probe)
	}

	// Substrate removed on_resume (tag 3). Inspect the wire payload so this
	// also catches an obsolete field preserved as unknown protobuf data.
	wire, err := proto.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	for len(wire) > 0 {
		num, typ, n := protowire.ConsumeTag(wire)
		if n < 0 {
			t.Fatal(protowire.ParseError(n))
		}
		if num == 3 {
			t.Fatal("snapshot config emits removed on_resume protobuf tag 3")
		}
		wire = wire[n:]
		n = protowire.ConsumeFieldValue(num, typ, wire)
		if n < 0 {
			t.Fatal(protowire.ParseError(n))
		}
		wire = wire[n:]
	}
}

type resumeControlClient struct {
	ateapipb.ControlClient
	actor *ateapipb.Actor
}

func (m *resumeControlClient) ResumeActor(context.Context, *ateapipb.ResumeActorRequest, ...grpc.CallOption) (*ateapipb.ResumeActorResponse, error) {
	return &ateapipb.ResumeActorResponse{Actor: m.actor}, nil
}

func TestClient_ResumeActor_WorkerIPs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		actor *ateapipb.Actor
		want  string
	}{
		{name: "no status", actor: &ateapipb.Actor{}},
		{name: "no assignment", actor: &ateapipb.Actor{Status: &ateapipb.ActorStatus{}}},
		{name: "no IPs", actor: &ateapipb.Actor{Status: &ateapipb.ActorStatus{WorkerAssignment: &ateapipb.WorkerAssignment{}}}},
		{name: "single IP", actor: &ateapipb.Actor{Status: &ateapipb.ActorStatus{WorkerAssignment: &ateapipb.WorkerAssignment{WorkerPodIps: []string{"10.244.1.42"}}}}, want: "10.244.1.42"},
		{name: "multiple IPs", actor: &ateapipb.Actor{Status: &ateapipb.ActorStatus{WorkerAssignment: &ateapipb.WorkerAssignment{WorkerPodIps: []string{"10.244.1.42", "fd00::42"}}}}, want: "10.244.1.42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{control: &resumeControlClient{actor: tc.actor}}
			actor, ip, err := c.ResumeActor(context.Background(), "test-ns", "test-actor")
			if err != nil {
				t.Fatal(err)
			}
			if actor != tc.actor || ip != tc.want {
				t.Fatalf("ResumeActor returned actor %v, IP %q; want actor %v, IP %q", actor, ip, tc.actor, tc.want)
			}
		})
	}
}

type mockControlClient struct {
	ateapipb.ControlClient

	mu             sync.Mutex
	deleteCalls    []*ateapipb.DeleteActorRequest
	getCalls       []*ateapipb.GetActorRequest
	deleteErr      error
	actorRemaining int // Number of GetActor calls before returning NotFound
}

func (m *mockControlClient) DeleteActor(ctx context.Context, req *ateapipb.DeleteActorRequest, opts ...grpc.CallOption) (*ateapipb.Actor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls = append(m.deleteCalls, req)
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}
	return &ateapipb.Actor{}, nil
}

func (m *mockControlClient) GetActor(ctx context.Context, req *ateapipb.GetActorRequest, opts ...grpc.CallOption) (*ateapipb.Actor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls = append(m.getCalls, req)
	if m.actorRemaining > 0 {
		m.actorRemaining--
		return &ateapipb.Actor{
			Metadata: &ateapipb.ResourceMetadata{
				Atespace: req.GetActor().GetAtespace(),
				Name:     req.GetActor().GetName(),
			},
			Status: &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_DELETING},
		}, nil
	}
	return nil, status.Error(codes.NotFound, "actor not found")
}

func TestClient_DeleteActor_AnyStateTrue(t *testing.T) {
	mock := &mockControlClient{
		actorRemaining: 0,
	}
	c := &Client{control: mock}
	ctx := context.Background()

	err := c.DeleteActor(ctx, "test-ns", "test-actor")
	if err != nil {
		t.Fatalf("DeleteActor failed: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.deleteCalls) != 1 {
		t.Fatalf("expected 1 DeleteActor call, got %d", len(mock.deleteCalls))
	}
	req := mock.deleteCalls[0]
	if !req.GetAnyState() {
		t.Errorf("expected AnyState to be true, got %v", req.GetAnyState())
	}
	if req.GetActor().GetAtespace() != "test-ns" || req.GetActor().GetName() != "test-actor" {
		t.Errorf("unexpected actor ref in request: %v", req.GetActor())
	}
}

func TestClient_DeleteActor_PollsUntilNotFound(t *testing.T) {
	oldInterval := actorDeletionPollInterval
	actorDeletionPollInterval = 10 * time.Millisecond
	defer func() { actorDeletionPollInterval = oldInterval }()

	mock := &mockControlClient{
		actorRemaining: 3,
	}
	c := &Client{control: mock}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := c.DeleteActor(ctx, "test-ns", "test-actor")
	if err != nil {
		t.Fatalf("DeleteActor failed: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	// 1 fast-path GetActor call + 3 polling calls (last one returns NotFound)
	if len(mock.getCalls) != 4 {
		t.Errorf("expected 4 GetActor calls before NotFound, got %d", len(mock.getCalls))
	}
}

func TestClient_DeleteActor_NotFoundIsIgnored(t *testing.T) {
	mock := &mockControlClient{
		deleteErr: status.Error(codes.NotFound, "actor already gone"),
	}
	c := &Client{control: mock}
	ctx := context.Background()

	err := c.DeleteActor(ctx, "test-ns", "test-actor")
	if err != nil {
		t.Fatalf("expected nil error when actor is NotFound, got: %v", err)
	}
}

func TestClient_DeleteActor_PropagatesRPCError(t *testing.T) {
	mock := &mockControlClient{
		deleteErr: errors.New("internal atelet failure"),
	}
	c := &Client{control: mock}
	ctx := context.Background()

	err := c.DeleteActor(ctx, "test-ns", "test-actor")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
