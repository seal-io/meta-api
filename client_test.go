package api

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/seal-io/meta/api/schema"
)

func TestClient(t *testing.T) {
	var udx = "unix:" + filepath.Join(os.TempDir(), "meta.sock")
	var cmd = testingServer(t)

	var eg, runCtx = errgroup.WithContext(context.Background())
	eg.Go(func() error {
		var server = exec.CommandContext(runCtx, cmd, "grpc",
			"--log-debug",
			"--log-stdout",
			"--serve-on="+udx,
			"--storage-provider=tencent_cloud",
			"--storage-region=ap-guangzhou",
			"--storage-bucket=seal-meta-1303613262")
		server.Stdout = testingOutput(t.Log)
		server.Stderr = testingOutput(t.Error)
		var err = server.Run()
		if err != nil {
			return err
		}
		return nil
	})
	eg.Go(func() error {
		var cli, err = GetClient(runCtx, udx)
		if err != nil {
			return err
		}
		defer func() { _ = cli.Close() }()
		err = cli.IngestAll(runCtx, time.Time{}, func(currentWindow int32, v schema.DatasetIngestResponseBody) error {
			switch v.(type) {
			case *schema.DatasetIngestResponse_ComplianceLicenseTags:
				t.Logf("ingested compliance license tags of window %d",
					currentWindow)
			case *schema.DatasetIngestResponse_ComplianceLicenses:
				t.Logf("ingested compliance license entities of window %d",
					currentWindow)
			case *schema.DatasetIngestResponse_WeaknessVulnerabilityTags:
				t.Logf("ingested weakness vulnerability tags of window %d",
					currentWindow)
			case *schema.DatasetIngestResponse_WeaknessVulnerabilities:
				t.Logf("ingested weakness vulnerability entities of window %d",
					currentWindow)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return context.Canceled
	})
	var err = eg.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("error testing: %v", err)
	}
}

func testingServer(t *testing.T) string {
	var bin = "seal-meta-" + runtime.GOOS + "-" + runtime.GOARCH
	var path, _ = filepath.Abs(filepath.Join("../bin", bin))
	var _, err = os.Stat(path)
	if err != nil {
		t.Skipf("error getting testing server binary: %v", err)
	}
	return path
}

type testingOutput func(args ...any)

func (output testingOutput) Write(p []byte) (n int, err error) {
	if output != nil {
		if len(p) != 0 {
			output(string(p))
		}
	}
	return len(p), nil
}
