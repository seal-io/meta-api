package api

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/seal-io/meta/api/schema"
)

func TestClient(t *testing.T) {
	const udx = "unix:/tmp/meta.sock"
	var cmd = testingServer(t)

	var eg, runCtx = errgroup.WithContext(context.Background())
	eg.Go(func() error {
		var ctx, cancel = context.WithCancel(runCtx)
		defer cancel()
		var server = exec.CommandContext(ctx, cmd, "grpc",
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
		err = cli.Ingest(runCtx, true, func(currentPage, nextPage, pageSize, totalSize int64, v schema.DatasetIngestResponseList) error {
			switch v.(type) {
			case *schema.DatasetIngestResponse_ComplianceLicenseTag:
				t.Logf("ingested compliance license tags, page: %d, page size: %d, total: %d",
					currentPage, pageSize, totalSize)
			case *schema.DatasetIngestResponse_ComplianceLicense:
				t.Logf("ingested compliance license entities, page: %d, page size: %d, total: %d",
					currentPage, pageSize, totalSize)
			case *schema.DatasetIngestResponse_RiskSecretLeakTag:
				t.Logf("ingested risk secret leak tags, page: %d, page size: %d, total: %d",
					currentPage, pageSize, totalSize)
			case *schema.DatasetIngestResponse_RiskSecretLeak:
				t.Logf("ingested risk secret leak entities, page: %d, page size: %d, total: %d",
					currentPage, pageSize, totalSize)
			case *schema.DatasetIngestResponse_WeaknessVulnerabilityTag:
				t.Logf("ingested weakness vulnerability tags, page: %d, page size: %d, total: %d",
					currentPage, pageSize, totalSize)
			case *schema.DatasetIngestResponse_WeaknessVulnerability:
				t.Logf("ingested weakness vulnerability entities, page: %d, page size: %d, total: %d",
					currentPage, pageSize, totalSize)
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
