package controllers

// import (
// 	"context"
// 	"fmt"
// 	"testing"
// 	"time"

// 	"github.com/go-logr/logr"
// 	"github.com/go-logr/logr/testr"
// 	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
// 	"github.com/hashicorp/vault-secrets-operator/consts"
// 	"github.com/stretchr/testify/require"
// 	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
// 	"k8s.io/client-go/tools/record"
// 	"nhooyr.io/websocket"
// 	"sigs.k8s.io/controller-runtime/pkg/event"
// )

// func TestVaultStaticSecretReconciler_streamStaticSecretEvents(t *testing.T) {
// 	t.Parallel()

// 	sourceCh := make(chan event.GenericEvent, 1)
// 	recorder := record.NewFakeRecorder(5)
// 	r := &VaultStaticSecretReconciler{
// 		Recorder: recorder,
// 		SourceCh: sourceCh,
// 	}

// 	vss := &secretsv1beta1.VaultStaticSecret{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name:      "example",
// 			Namespace: "default",
// 		},
// 		Spec: secretsv1beta1.VaultStaticSecretSpec{
// 			Namespace: "team-a",
// 			VaultStaticSecretCommon: secretsv1beta1.VaultStaticSecretCommon{
// 				Mount: "kv",
// 				Path:  "app/config",
// 				Type:  consts.KVSecretTypeV2,
// 			},
// 		},
// 	}

// 	eventJSON := []byte(fmt.Sprintf(`{"data":{"event":{"metadata":{"path":"%s","modified":"true"}},"namespace":"/%s"}}`,
// 		"kv/data/app/config", vss.Spec.Namespace))

// 	wsClient := &fakeWebsocketClient{
// 		conn: newFakeWebsocketConn(eventJSON),
// 	}

// 	ctx, cancel := context.WithCancel(context.Background())
// 	t.Cleanup(cancel)
// 	ctx = logr.NewContext(ctx, testr.New(t))

// 	errCh := make(chan error, 1)
// 	go func() {
// 		errCh <- r.streamStaticSecretEvents(ctx, vss, wsClient)
// 	}()

// 	select {
// 	case evt := <-sourceCh:
// 		require.Equal(t, vss.Name, evt.Object.GetName())
// 		require.Equal(t, vss.Namespace, evt.Object.GetNamespace())
// 	case <-time.After(2 * time.Second):
// 		t.Fatal("did not receive requeue event")
// 	}

// 	cancel()

// 	err := <-errCh
// 	require.Error(t, err)
// 	require.Contains(t, err.Error(), "context canceled")
// }

// type fakeWebsocketClient struct {
// 	conn websocketConn
// 	err  error
// }

// func (f *fakeWebsocketClient) Connect(context.Context) (websocketConn, error) {
// 	if f.err != nil {
// 		return nil, f.err
// 	}
// 	return f.conn, nil
// }

// type fakeWebsocketConn struct {
// 	messages chan []byte
// }

// func newFakeWebsocketConn(msgs ...[]byte) *fakeWebsocketConn {
// 	ch := make(chan []byte, len(msgs))
// 	for _, msg := range msgs {
// 		ch <- msg
// 	}
// 	return &fakeWebsocketConn{
// 		messages: ch,
// 	}
// }

// func (f *fakeWebsocketConn) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
// 	select {
// 	case msg := <-f.messages:
// 		return websocket.MessageText, msg, nil
// 	case <-ctx.Done():
// 		return 0, nil, ctx.Err()
// 	}
// }

// func (f *fakeWebsocketConn) Close(websocket.StatusCode, string) error {
// 	return nil
// }
