package api

import (
	"context"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/seal-io/meta-api/schema"
)

// Client holds the actions for receiving from the exposing service.
type Client interface {
	// Ingest ingests all dataset from the exposing service,
	// and parses dataset with the given IngestParser.
	Ingest(ctx context.Context, update bool, parse IngestParser) (err error)

	// Close closes the client.
	Close() error
}

// GetClient returns the Client.
func GetClient(ctx context.Context, listenOn string) (Client, error) {
	var opts = []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(128 * 1024 * 1024)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	var cc, err = grpc.DialContext(ctx, listenOn, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "error dialing %s", listenOn)
	}
	var cli = &client{
		cc: cc,
	}
	return cli, nil
}

type client struct {
	cc *grpc.ClientConn
}

// IngestParser is the parser to parse the given api.DatasetIngestResponseList.
type IngestParser func(currentPage, nextPage, pageSize, totalSize int64, list schema.DatasetIngestResponseList) error

func (in *client) Ingest(ctx context.Context, update bool, parse IngestParser) error {
	var cli, err = schema.NewDatasetServiceClient(in.cc).Ingest(ctx)
	if err != nil {
		return errors.Wrap(err, "error creating ingest client")
	}
	for _, typ := range []schema.DatasetIngestRequestType{
		schema.DatasetIngestRequestType_Compliance_License_Tag,
		schema.DatasetIngestRequestType_Compliance_License,
		schema.DatasetIngestRequestType_Risk_Secret_Leak_Tag,
		schema.DatasetIngestRequestType_Risk_Secret_Leak,
		schema.DatasetIngestRequestType_Weakness_Vulnerability_Tag,
		schema.DatasetIngestRequestType_Weakness_Vulnerability,
	} {
		var page int64
		for page >= 0 {
			var req = &schema.DatasetIngestRequest{
				Page: page,
				Type: typ,
			}
			err = cli.Send(req)
			if err != nil {
				return errors.Wrap(err, "error sending ingest request")
			}
			var resp *schema.DatasetIngestResponse
			resp, err = cli.Recv()
			if err != nil {
				return errors.Wrap(err, "error receiving ingest response")
			}
			var currentPage = page
			var nextPage = resp.GetNextPage()
			var pageSize = resp.GetPerPage()
			var total = resp.GetTotal()
			var list = resp.GetList()
			if parse != nil && resp.GetList() != nil {
				err = parse(currentPage, nextPage, pageSize, total, list)
				if err != nil {
					return errors.Wrap(err, "error parsing ingest response")
				}
			}
			page = nextPage
		}
	}
	return nil
}

func (in *client) Close() error {
	if in.cc != nil {
		return in.cc.Close()
	}
	return nil
}
