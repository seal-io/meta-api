package api

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/seal-io/meta/api/schema"
)

// Client holds the actions for receiving from the exposing service.
type Client interface {
	// Ingest ingests specified type dataset from the exposing service,
	// and parses dataset with the given IngestParser.
	Ingest(ctx context.Context, typ schema.DatasetIngestRequestType, since time.Time, parse IngestParser) (err error)

	// IngestAll ingests all types dataset from the exposing service,
	// and parses dataset with the given IngestParser.
	IngestAll(ctx context.Context, since time.Time, parse IngestParser) (err error)

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

// IngestParser is the parser to parse the given api.DatasetIngestResponseBody.
type IngestParser func(currentWindow int32, body schema.DatasetIngestResponseBody) error

func (in *client) Ingest(ctx context.Context, typ schema.DatasetIngestRequestType, since time.Time, parse IngestParser) error {
	var cli, err = schema.NewDatasetServiceClient(in.cc).Ingest(ctx)
	if err != nil {
		return errors.Wrap(err, "error creating ingest client")
	}
	var window int32
	for window >= 0 {
		var req = &schema.DatasetIngestRequest{
			Window: window,
			Type:   typ,
		}
		if !since.IsZero() {
			req.Since = timestamppb.New(since)
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
		if parse != nil && resp.GetBody() != nil {
			err = parse(window, resp.GetBody())
			if err != nil {
				return errors.Wrap(err, "error parsing ingest response")
			}
		}
		window = resp.GetNextWindow()
		if resp.NextWindow == nil {
			window = -1
		}
	}
	return nil
}

func (in *client) IngestAll(ctx context.Context, since time.Time, parse IngestParser) error {
	for typ := 0; typ < len(schema.DatasetIngestRequestType_name); typ++ {
		var err = in.Ingest(ctx, schema.DatasetIngestRequestType(typ), since, parse)
		if err != nil {
			return err
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
